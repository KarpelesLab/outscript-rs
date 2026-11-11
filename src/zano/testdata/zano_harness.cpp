// Reference harness for outscript's Zano module. NOT compiled by cargo.
//
// It links against the libraries of Zano's own C++ tree (crypto, common,
// currency_core) and drives the reference functions:
//
//   zano_harness vectors
//       prints test vectors (src/zano/testdata/cxx_vectors.txt): the key
//       derivation of the HF6 payload encryption, ChaCha20, what
//       `encrypt_payload_items` does to a version 4 and to a version 3
//       transaction, and the wallet blobs (`finalize_tx_param`,
//       `finalized_tx`) of the three layouts with known field values.
//   zano_harness sign <view_secret> <spend_secret> <unsigned_blob> <signed_blob>
//       what `wallet2::sign_transfer` does: decrypts and parses an unsigned
//       transaction, runs `construct_tx`, writes the signed blob.
//   zano_harness check <view_secret> <spend_secret> <signed_blob> [<view_secret> <spend_secret>]...
//       parses a signed blob and validates its transaction as the daemon
//       does short of the chain (`validate_tx_semantic`, the signature of
//       each input against the ring of its source, range proofs, balance
//       proof, asset surjection proof), then prints what each of the given
//       accounts finds in it (`lookup_acc_outs`, `decrypt_payload_items`).
//
// Built against hyle-team/zano d1f2d9655d1aebf05d4ed281f2c691f9f9078bd1
// (2.2.3.608); see cxx_harness_build.txt for how, and for the script that
// makes cxx_sign_vectors.txt and cxx/*.signed.bin with it. The layouts of the older
// releases are the structures of those releases, copied below from tags
// 2.1.0.382 and 2.1.19.477 and serialized by the same library.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <vector>

#include "include_base_utils.h"
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/clsag.h"
#include "currency_core/account.h"
#include "currency_core/crypto_config.h"
#include "currency_core/currency_basic.h"
#include "currency_core/currency_format_utils.h"
#include "currency_core/tx_semantic_validation.h"
#include "serialization/serialization.h"

using namespace currency;

namespace currency
{
  // Defined in currency_format_utils.cpp, not declared in its header.
  void encrypt_decrypt_key_derivation_for_sender(const crypto::public_key& tx_pub, const crypto::secret_key& spend_sec, crypto::key_derivation& in_out);
}
using epee::string_tools::buff_to_hex_nodelimer;
template<class T> static std::string ph(const T& t) { return epee::string_tools::pod_to_hex(t); }

// ---------------------------------------------------------------------------
// The wallet structures of the older releases.

// Zano 2.1.8.428 to 2.1.19.477: sources name their asset.
namespace layout_b
{
  struct tx_source_entry
  {
    typedef currency::tx_source_entry::output_entry output_entry;
    std::vector<output_entry> outputs;
    uint64_t real_output = 0;
    crypto::public_key real_out_tx_key = currency::null_pkey;
    crypto::scalar_t real_out_amount_blinding_mask = 0;
    crypto::scalar_t real_out_asset_id_blinding_mask = 0;
    size_t real_output_in_tx_index = 0;
    uint64_t amount = 0;
    uint64_t transfer_index = 0;
    crypto::hash multisig_id = currency::null_hash;
    size_t ms_sigs_count = 0;
    size_t ms_keys_count = 0;
    bool separately_signed_tx_complete = false;
    std::string htlc_origin;
    crypto::public_key asset_id = currency::native_coin_asset_id;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_amount_blinding_mask)
      FIELD(real_out_asset_id_blinding_mask)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(transfer_index)
      FIELD(multisig_id)
      FIELD(ms_sigs_count)
      FIELD(ms_keys_count)
      FIELD(separately_signed_tx_complete)
      FIELD(htlc_origin)
      FIELD(asset_id)
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    uint64_t amount = 0;
    std::list<account_public_address> addr;
    size_t minimum_sigs = 0;
    uint64_t amount_to_provide = 0;
    uint64_t unlock_time = 0;
    destination_option_htlc_out htlc_options;
    crypto::public_key asset_id = currency::native_coin_asset_id;
    uint64_t flags = 0;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(amount)
      FIELD(addr)
      FIELD(minimum_sigs)
      FIELD(amount_to_provide)
      FIELD(unlock_time)
      FIELD(htlc_options)
      FIELD(asset_id)
      FIELD(flags)
    END_SERIALIZE()
  };
}

// Zano 2.0 and 2.1.0.382 to 2.1.7.424: sources do not name their asset.
namespace layout_a
{
  struct tx_source_entry
  {
    typedef currency::tx_source_entry::output_entry output_entry;
    std::vector<output_entry> outputs;
    uint64_t real_output = 0;
    crypto::public_key real_out_tx_key = currency::null_pkey;
    crypto::scalar_t real_out_amount_blinding_mask = 0;
    crypto::scalar_t real_out_asset_id_blinding_mask = 0;
    size_t real_output_in_tx_index = 0;
    uint64_t amount = 0;
    uint64_t transfer_index = 0;
    crypto::hash multisig_id = currency::null_hash;
    size_t ms_sigs_count = 0;
    size_t ms_keys_count = 0;
    bool separately_signed_tx_complete = false;
    std::string htlc_origin;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_amount_blinding_mask)
      FIELD(real_out_asset_id_blinding_mask)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(transfer_index)
      FIELD(multisig_id)
      FIELD(ms_sigs_count)
      FIELD(ms_keys_count)
      FIELD(separately_signed_tx_complete)
      FIELD(htlc_origin)
    END_SERIALIZE()
  };

  typedef layout_b::tx_destination_entry tx_destination_entry;
}

// `finalize_tx_param` and `finalized_tx` did not change but for the types
// of their sources and destinations (the generation context of a separately
// signed transaction, which outscript does not read, is left out).
template<class source_t, class destination_t>
struct finalize_tx_param_t
{
  uint64_t unlock_time = 0;
  std::vector<currency::extra_v> extra;
  std::vector<currency::attachment_v> attachments;
  currency::account_public_address crypt_address{};
  uint8_t tx_outs_attr = 0;
  bool shuffle = false;
  uint8_t flags = 0;
  crypto::hash multisig_id = currency::null_hash;
  std::vector<source_t> sources;
  std::vector<uint64_t> selected_transfers;
  std::vector<destination_t> prepared_destinations;
  uint64_t expiration_time = 0;
  crypto::public_key spend_pub_key = currency::null_pkey;
  uint64_t tx_version = 0;
  size_t tx_hardfork_id = 0;
  uint64_t mode_separate_fee = 0;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(unlock_time)
    FIELD(extra)
    FIELD(attachments)
    FIELD(crypt_address)
    FIELD(tx_outs_attr)
    FIELD(shuffle)
    FIELD(flags)
    FIELD(multisig_id)
    FIELD(sources)
    FIELD(selected_transfers)
    FIELD(prepared_destinations)
    FIELD(expiration_time)
    FIELD(spend_pub_key)
    FIELD(tx_version)
    FIELD(tx_hardfork_id)
    FIELD(mode_separate_fee)
  END_SERIALIZE()
};

template<class ftp_t>
struct finalized_tx_t
{
  currency::transaction tx;
  crypto::hash tx_id = currency::null_hash;
  crypto::secret_key one_time_key = currency::null_skey;
  ftp_t ftp;
  std::string htlc_origin;
  std::vector<serializable_pair<uint64_t, crypto::key_image>> outs_key_images;
  crypto::key_derivation derivation{};
  bool was_not_prepared = false;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(tx)
    FIELD(tx_id)
    FIELD(one_time_key)
    FIELD(ftp)
    FIELD(htlc_origin)
    FIELD(outs_key_images)
    FIELD(derivation)
    FIELD(was_not_prepared)
  END_SERIALIZE()
};

typedef finalize_tx_param_t<layout_a::tx_source_entry, layout_a::tx_destination_entry> ftp_a;
typedef finalize_tx_param_t<layout_b::tx_source_entry, layout_b::tx_destination_entry> ftp_b;

// ---------------------------------------------------------------------------
// Helpers.

static std::string hex(const std::string& s)
{
  return s.empty() ? std::string("-") : buff_to_hex_nodelimer(s);
}

static std::string unhex(const std::string& s)
{
  std::string r;
  if (s != "-" && !epee::string_tools::parse_hexstr_to_binbuff(s, r))
    throw std::runtime_error("bad hex: " + s);
  return r;
}

template<class T>
static T pod(const std::string& h)
{
  T t{};
  if (!epee::string_tools::hex_to_pod(h, t))
    throw std::runtime_error("bad pod hex: " + h);
  return t;
}

// Deterministic filler: byte n is (n * 197 + 13) % 251, counting on.
static uint64_t g_fill = 0;
static void fill(void* p, size_t n)
{
  uint8_t* b = static_cast<uint8_t*>(p);
  for (size_t i = 0; i < n; ++i, ++g_fill)
    b[i] = static_cast<uint8_t>((g_fill * 197 + 13) % 251);
}
template<class T> static void fill_pod(T& t) { fill(&t, sizeof t); }
static uint64_t fill_u64() { uint64_t v; fill(&v, sizeof v); return v; }
static std::string fill_str(size_t n) { std::string s(n, '\0'); fill(&s[0], n); return s; }
// A reduced scalar.
static crypto::secret_key fill_scalar()
{
  crypto::scalar_t s;
  fill(&s, sizeof s);
  s.m_u64[3] &= 0x0fffffffffffffffull;
  return s.as_secret_key();
}

static account_keys make_keys(const crypto::secret_key& spend, const crypto::secret_key& view)
{
  account_keys k{};
  k.spend_secret_key = spend;
  k.view_secret_key = view;
  if (!crypto::secret_key_to_public_key(spend, k.account_address.spend_public_key) ||
      !crypto::secret_key_to_public_key(view, k.account_address.view_public_key))
    throw std::runtime_error("bad secret key");
  k.account_address.flags = 0;
  return k;
}

static std::string read_file(const char* path)
{
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error(std::string("cannot read ") + path);
  std::stringstream ss; ss << f.rdbuf();
  return ss.str();
}

static void write_file(const char* path, const std::string& data)
{
  std::ofstream f(path, std::ios::binary);
  f.write(data.data(), data.size());
  if (!f) throw std::runtime_error(std::string("cannot write ") + path);
}

// ---------------------------------------------------------------------------
// Field dumps, compared token by token with what outscript parses.

static std::string dump_ref(const txout_ref_v& r)
{
  if (r.type() == typeid(uint64_t))
    return "g" + std::to_string(boost::get<uint64_t>(r));
  const ref_by_id& id = boost::get<ref_by_id>(r);
  return "r" + ph(id.tx_id) + ":" + std::to_string(id.n);
}

static void dump_asset(std::ostream& o, const layout_a::tx_source_entry&) { o << " -"; }
static void dump_asset(std::ostream& o, const layout_b::tx_source_entry& s) { o << " " << ph(s.asset_id); }
static void dump_asset(std::ostream& o, const currency::tx_source_entry& s) { o << " " << ph(s.asset_id); }

template<class source_t>
static void dump_source(std::ostream& o, const source_t& s)
{
  o << " " << s.outputs.size();
  for (const auto& e : s.outputs)
    o << " " << dump_ref(e.out_reference) << " " << ph(e.stealth_address) << " " << ph(e.concealing_point)
      << " " << ph(e.amount_commitment) << " " << ph(e.blinded_asset_id);
  o << " " << s.real_output << " " << ph(s.real_out_tx_key) << " " << ph(s.real_out_amount_blinding_mask)
    << " " << ph(s.real_out_asset_id_blinding_mask) << " " << s.real_output_in_tx_index << " " << s.amount
    << " " << s.transfer_index << " " << ph(s.multisig_id) << " " << s.ms_sigs_count << " " << s.ms_keys_count
    << " " << (s.separately_signed_tx_complete ? 1 : 0) << " " << hex(s.htlc_origin);
  dump_asset(o, s);
}

static void dump_addr(std::ostream& o, const account_public_address& a)
{
  o << " " << ph(a.spend_public_key) << " " << ph(a.view_public_key) << " " << static_cast<unsigned>(a.flags);
}
static void dump_addr(std::ostream& o, const address_v& a) { dump_addr(o, boost::get<account_public_address>(a)); }

static void dump_pid(std::ostream& o, const layout_b::tx_destination_entry&) { o << " -"; }
static void dump_pid(std::ostream& o, const currency::tx_destination_entry& d) { o << " " << d.payment_id; }

template<class dest_t>
static void dump_dest(std::ostream& o, const dest_t& d)
{
  o << " " << d.amount << " " << d.addr.size();
  for (const auto& a : d.addr)
    dump_addr(o, a);
  o << " " << d.minimum_sigs << " " << d.amount_to_provide << " " << d.unlock_time << " " << d.htlc_options.expiration
    << " " << ph(d.htlc_options.htlc_hash) << " " << ph(d.asset_id) << " " << d.flags;
  dump_pid(o, d);
}

template<class ftp_t>
static void dump_ftp(std::ostream& o, const ftp_t& f)
{
  o << " " << f.unlock_time << " " << hex(t_serializable_object_to_blob(f.extra)) << " " << hex(t_serializable_object_to_blob(f.attachments));
  dump_addr(o, f.crypt_address);
  o << " " << static_cast<unsigned>(f.tx_outs_attr) << " " << (f.shuffle ? 1 : 0) << " " << static_cast<unsigned>(f.flags)
    << " " << ph(f.multisig_id) << " " << f.sources.size();
  for (const auto& s : f.sources)
    dump_source(o, s);
  o << " " << f.selected_transfers.size();
  for (uint64_t t : f.selected_transfers)
    o << " " << t;
  o << " " << f.prepared_destinations.size();
  for (const auto& d : f.prepared_destinations)
    dump_dest(o, d);
  o << " " << f.expiration_time << " " << ph(f.spend_pub_key) << " " << f.tx_version << " " << f.tx_hardfork_id
    << " " << f.mode_separate_fee;
}

template<class fin_t>
static void dump_fin(std::ostream& o, const fin_t& f)
{
  // The ftp is the one of the line before.
  o << " " << hex(t_serializable_object_to_blob(f.tx)) << " " << ph(f.tx_id) << " " << ph(f.one_time_key);
  o << " " << hex(f.htlc_origin) << " " << f.outs_key_images.size();
  for (const auto& p : f.outs_key_images)
    o << " " << p.first << " " << ph(p.second);
  o << " " << ph(f.derivation) << " " << (f.was_not_prepared ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Blobs with known field values.

static void set_asset(layout_a::tx_source_entry&) {}
static void set_asset(layout_b::tx_source_entry& s) { fill_pod(s.asset_id); }
static void set_asset(currency::tx_source_entry& s) { fill_pod(s.asset_id); }
static void add_addr(std::list<account_public_address>& l) { account_public_address a{}; fill_pod(a.spend_public_key); fill_pod(a.view_public_key); a.flags = static_cast<uint8_t>(fill_u64()); l.push_back(a); }
static void add_addr(std::list<address_v>& l) { account_public_address a{}; fill_pod(a.spend_public_key); fill_pod(a.view_public_key); a.flags = static_cast<uint8_t>(fill_u64()); l.push_back(a); }
static void set_pid(layout_b::tx_destination_entry&) {}
static void set_pid(currency::tx_destination_entry& d) { d.payment_id = fill_u64(); }

template<class ftp_t>
static void fill_ftp(ftp_t& f)
{
  f.unlock_time = fill_u64();
  f.extra.push_back(tx_comment{fill_str(5)});
  extra_user_data ud; ud.buff = fill_str(3);
  f.extra.push_back(ud);
  tx_service_attachment sa{};
  sa.service_id = "P"; sa.instruction = fill_str(2); sa.body = fill_str(9); sa.flags = 1;
  sa.security.emplace_back(); fill_pod(sa.security.back());
  f.attachments.push_back(sa);
  fill_pod(f.crypt_address.spend_public_key); fill_pod(f.crypt_address.view_public_key); f.crypt_address.flags = 1;
  f.tx_outs_attr = 1;
  f.shuffle = true;
  f.flags = 0; // a separately signed transaction carries its generation context
  fill_pod(f.multisig_id);
  for (size_t i = 0; i < 2; ++i)
  {
    f.sources.emplace_back();
    auto& s = f.sources.back();
    for (size_t j = 0; j < 2 + i; ++j)
    {
      s.outputs.emplace_back();
      auto& e = s.outputs.back();
      if (i == 1 && j == 1)
      {
        ref_by_id id{}; fill_pod(id.tx_id); id.n = 7;
        e.out_reference = id;
      }
      else
        e.out_reference = fill_u64();
      fill_pod(e.stealth_address); fill_pod(e.concealing_point); fill_pod(e.amount_commitment); fill_pod(e.blinded_asset_id);
    }
    s.real_output = i;
    fill_pod(s.real_out_tx_key);
    s.real_out_amount_blinding_mask = crypto::scalar_t(fill_scalar());
    s.real_out_asset_id_blinding_mask = crypto::scalar_t(fill_scalar());
    s.real_output_in_tx_index = fill_u64();
    s.amount = fill_u64();
    s.transfer_index = fill_u64();
    fill_pod(s.multisig_id);
    s.ms_sigs_count = 0;
    s.ms_keys_count = fill_u64();
    s.separately_signed_tx_complete = (i == 1);
    s.htlc_origin = i == 1 ? fill_str(4) : std::string();
    set_asset(s);
  }
  f.selected_transfers = {3, 300, 70000};
  for (size_t i = 0; i < 3; ++i)
  {
    f.prepared_destinations.emplace_back();
    auto& d = f.prepared_destinations.back();
    d.amount = fill_u64();
    for (size_t j = 0; j < 1 + (i == 2 ? 1 : 0); ++j)
      add_addr(d.addr);
    d.minimum_sigs = fill_u64();
    d.amount_to_provide = fill_u64();
    d.unlock_time = fill_u64();
    d.htlc_options.expiration = fill_u64();
    fill_pod(d.htlc_options.htlc_hash);
    fill_pod(d.asset_id);
    d.flags = i;
    set_pid(d);
  }
  f.expiration_time = fill_u64();
  fill_pod(f.spend_pub_key);
  f.tx_version = 2 + fill_u64() % 3;
  f.tx_hardfork_id = fill_u64();
  f.mode_separate_fee = fill_u64();
}

template<class ftp_t, class fin_t>
static void blob_vectors(const char* layout, const transaction& tx, const crypto::secret_key& view)
{
  ftp_t f{};
  fill_ftp(f);
  std::string blob = t_serializable_object_to_blob(f);
  ftp_t back{};
  if (!t_unserializable_object_from_blob(back, blob) || t_serializable_object_to_blob(back) != blob)
    throw std::runtime_error("ftp round trip");
  crypto::chacha_crypt_legacy(blob, view);
  std::cout << "ftp " << layout << " " << ph(view) << " " << hex(blob);
  dump_ftp(std::cout, f);
  std::cout << "\n";

  fin_t fin{};
  fin.tx = tx;
  fill_pod(fin.tx_id);
  fin.one_time_key = fill_scalar();
  fin.ftp = f;
  fin.htlc_origin = fill_str(6);
  for (size_t i = 0; i < 2; ++i)
  {
    crypto::key_image ki; fill_pod(ki);
    fin.outs_key_images.push_back(make_serializable_pair(fill_u64(), ki));
  }
  fill_pod(fin.derivation);
  fin.was_not_prepared = true;
  blob = t_serializable_object_to_blob(fin);
  fin_t fback{};
  if (!t_unserializable_object_from_blob(fback, blob) || t_serializable_object_to_blob(fback) != blob)
    throw std::runtime_error("finalized round trip");
  crypto::chacha_crypt_legacy(blob, view);
  std::cout << "fin " << layout << " " << ph(view) << " " << hex(blob);
  dump_fin(std::cout, fin);
  std::cout << "\n";
}

// ---------------------------------------------------------------------------
// Payload encryption.

static std::string dump_items(const std::vector<payload_items_v>& items)
{
  std::ostringstream o;
  for (const auto& i : items)
  {
    if (i.type() == typeid(tx_comment))
      o << " c:" << hex(boost::get<tx_comment>(i).comment);
    else if (i.type() == typeid(tx_service_attachment))
    {
      const auto& sa = boost::get<tx_service_attachment>(i);
      o << " a:" << hex(sa.service_id) << ":" << hex(sa.body) << ":" << static_cast<unsigned>(sa.flags) << ":" << sa.security.size();
    }
    else if (i.type() == typeid(tx_payer))
      o << " p:" << ph(boost::get<tx_payer>(i).acc_addr.spend_public_key);
    else if (i.type() == typeid(tx_receiver))
      o << " r:" << ph(boost::get<tx_receiver>(i).acc_addr.spend_public_key);
  }
  return o.str().empty() ? std::string(" -") : o.str();
}

static transaction payload_vector(const char* name, uint64_t version)
{
  // Accounts as the wallet makes them: the view key follows from the spend key.
  auto account = []() {
    crypto::secret_key spend = fill_scalar(), view{};
    crypto::dependent_key(spend, view);
    return make_keys(spend, view);
  };
  account_keys sender = account();
  account_keys receiver = account();
  keypair tx_key{};
  tx_key.sec = fill_scalar();
  crypto::secret_key_to_public_key(tx_key.sec, tx_key.pub);

  transaction tx{};
  tx.version = version;
  tx.hardfork_id = version >= TRANSACTION_VERSION_POST_HF6 ? 7 : 5;
  txin_zc_input in{};
  fill_pod(in.k_image);
  in.key_offsets.push_back(uint64_t(5));
  tx.vin.push_back(in);

  auto attachment = [](const std::string& id, size_t body, uint8_t flags) {
    tx_service_attachment sa{};
    sa.service_id = id; sa.body = fill_str(body); sa.flags = flags;
    return sa;
  };
  tx.extra.push_back(tx_comment{fill_str(70)});
  tx.extra.push_back(attachment("P", 8, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY));
  tx.extra.push_back(tx_key.pub);
  extra_user_data ud; ud.buff = fill_str(4);
  tx.extra.push_back(ud);
  tx.extra.push_back(attachment("X", 130, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE));
  tx.attachment.push_back(attachment("Y", 5, 0));
  tx.attachment.push_back(attachment("Z", 33, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF));
  tx.attachment.push_back(attachment("W", 1, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY | TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE));
  if (version < TRANSACTION_VERSION_POST_HF6)
  {
    tx_payer payer{}; payer.acc_addr = sender.account_address;
    tx.attachment.push_back(payer);
    tx_receiver rcv{}; rcv.acc_addr = receiver.account_address;
    tx.extra.push_back(rcv);
    tx.attachment.push_back(tx_comment{fill_str(3)});
  }

  std::string before = t_serializable_object_to_blob(tx);
  crypto::key_derivation derivation{};
  encrypt_payload_items(tx, sender, receiver.account_address, tx_key, derivation);
  std::string after = t_serializable_object_to_blob(tx);

  std::vector<payload_items_v> income, outgoing, watch;
  if (!decrypt_payload_items(true, tx, receiver, income) || !decrypt_payload_items(false, tx, sender, outgoing))
    throw std::runtime_error("decrypt_payload_items");
  account_keys receiver_watch = receiver;
  receiver_watch.spend_secret_key = currency::null_skey;
  if (!decrypt_payload_items(true, tx, receiver_watch, watch))
    throw std::runtime_error("decrypt_payload_items (watch-only)");

  std::cout << name << " " << ph(sender.spend_secret_key) << " " << ph(sender.view_secret_key)
            << " " << ph(receiver.spend_secret_key) << " " << ph(receiver.view_secret_key)
            << " " << ph(tx_key.sec) << " " << ph(derivation) << " " << hex(before) << " " << hex(after) << "\n";
  std::cout << name << "_income" << dump_items(income) << "\n";
  std::cout << name << "_outgoing" << dump_items(outgoing) << "\n";
  std::cout << name << "_watch" << dump_items(watch) << "\n";
  return tx;
}

static int cmd_vectors()
{
  std::cout << "# Made by zano_harness.cpp (see cxx_harness_build.txt) from Zano's C++; do not edit.\n";
  // chacha_generate_key_and_iv: Keccak, rate 120 bytes, 40 bytes out.
  const char* domains[] = {CRYPTO_HDS_CHACHA_TX_PAYLOAD_ITEMS, CRYPTO_HDS_CHACHA_TX_PI_ISOLATE_AUDITABLE, CRYPTO_HDS_CHACHA_TX_PAYLOAD_SENDER_DER};
  size_t sizes[] = {32, 0, 200};
  for (size_t i = 0; i < 3; ++i)
  {
    char hdss[32];
    memcpy(hdss, domains[i], 32);
    std::string data = fill_str(sizes[i]);
    uint64_t index = i == 0 ? 0 : fill_u64();
    crypto::chacha_key key; crypto::chacha_iv iv;
    crypto::chacha_generate_key_and_iv(hdss, data.data(), data.size(), index, key, iv);
    std::cout << "key_iv " << hex(std::string(hdss, 32)) << " " << hex(data) << " " << index << " " << ph(key) << " " << ph(iv) << "\n";
  }
  for (size_t n : {size_t(1), size_t(64), size_t(65), size_t(200)})
  {
    crypto::chacha_key key; fill_pod(key);
    crypto::chacha_iv iv; fill_pod(iv);
    std::string plain = fill_str(n);
    std::cout << "chacha20 " << ph(key) << " " << ph(iv) << " " << hex(plain) << " " << hex(crypto::chacha20(key, iv, plain)) << "\n";
  }
  {
    crypto::secret_key spend = fill_scalar(), r = fill_scalar();
    crypto::public_key tx_pub; crypto::secret_key_to_public_key(r, tx_pub);
    crypto::key_derivation d; fill_pod(d);
    crypto::key_derivation e = d;
    encrypt_decrypt_key_derivation_for_sender(tx_pub, spend, e);
    std::cout << "sender_derivation " << ph(tx_pub) << " " << ph(spend) << " " << ph(d) << " " << ph(e) << "\n";
  }
  transaction tx4 = payload_vector("payload_v4", TRANSACTION_VERSION_POST_HF6);
  transaction tx3 = payload_vector("payload_v3", TRANSACTION_VERSION_POST_HF5);

  crypto::secret_key view = fill_scalar();
  blob_vectors<ftp_a, finalized_tx_t<ftp_a>>("a", tx3, view);
  blob_vectors<ftp_b, finalized_tx_t<ftp_b>>("b", tx3, view);
  blob_vectors<currency::finalize_tx_param, currency::finalized_tx>("c", tx4, view);
  return 0;
}

// ---------------------------------------------------------------------------
// Signing, as wallet2::sign_transfer does.

// wallet2::out_get_pub_key
static crypto::public_key out_get_pub_key(const tx_out_v& out_t)
{
  if (out_t.type() == typeid(tx_out_bare))
  {
    const tx_out_bare& out = boost::get<tx_out_bare>(out_t);
    return out.target.type() == typeid(txout_to_key) ? boost::get<txout_to_key>(out.target).key : null_pkey;
  }
  return boost::get<tx_out_zarcanum>(out_t).stealth_address;
}

static int cmd_sign(char** argv)
{
  account_keys keys = make_keys(pod<crypto::secret_key>(argv[1]), pod<crypto::secret_key>(argv[0]));
  std::string decrypted = crypto::chacha_crypt_legacy(read_file(argv[2]), keys.view_secret_key);

  finalized_tx ft{};
  if (!t_unserializable_object_from_blob(ft.ftp, decrypted))
    throw std::runtime_error("failed to parse the unsigned blob");
  if (t_serializable_object_to_blob(ft.ftp) != decrypted)
    throw std::runtime_error("the unsigned blob does not serialize back to itself");
  if (ft.ftp.spend_pub_key != keys.account_address.spend_public_key)
    throw std::runtime_error("keys mismatch");

  finalize_tx_param ftp = ft.ftp;
  if (!construct_tx(keys, ftp, ft))
    throw std::runtime_error("construct_tx failed");

  crypto::key_derivation derivation{};
  crypto::generate_key_derivation(keys.account_address.view_public_key, ft.one_time_key, derivation);
  for (size_t i = 0; i < ft.tx.vout.size(); ++i)
  {
    const crypto::public_key out_pk = out_get_pub_key(ft.tx.vout[i]);
    crypto::public_key ephemeral_pub{};
    crypto::derive_public_key(derivation, i, keys.account_address.spend_public_key, ephemeral_pub);
    if (out_pk == ephemeral_pub)
    {
      crypto::secret_key ephemeral_sec{};
      crypto::derive_secret_key(derivation, i, keys.spend_secret_key, ephemeral_sec);
      crypto::key_image ki{};
      crypto::generate_key_image(ephemeral_pub, ephemeral_sec, ki);
      ft.outs_key_images.push_back(make_serializable_pair(static_cast<uint64_t>(i), ki));
    }
  }
  std::string signed_blob = t_serializable_object_to_blob(ft);
  crypto::chacha_crypt_legacy(signed_blob, keys.view_secret_key);
  write_file(argv[3], signed_blob);
  std::cout << "signed " << ph(get_transaction_hash(ft.tx)) << "\n";
  return 0;
}

// ---------------------------------------------------------------------------
// Validation.

static bool check_input(const transaction& tx, size_t index, const crypto::hash& tx_id, const tx_source_entry& src)
{
  crypto::hash m = prepare_prefix_hash_for_sign(tx, index, tx_id);
  if (tx.vin[index].type() == typeid(txin_zc_input))
  {
    const txin_zc_input& in = boost::get<txin_zc_input>(tx.vin[index]);
    if (tx.signatures[index].type() != typeid(ZC_sig) || in.key_offsets.size() != src.outputs.size())
      return false;
    const ZC_sig& sig = boost::get<ZC_sig>(tx.signatures[index]);
    std::vector<crypto::CLSAG_GGX_input_ref_t> ring;
    for (const auto& o : src.outputs)
      ring.emplace_back(o.stealth_address, o.amount_commitment, o.blinded_asset_id);
    return crypto::verify_CLSAG_GGX(m, ring, sig.pseudo_out_amount_commitment, sig.pseudo_out_blinded_asset_id, in.k_image, sig.clsags_ggx);
  }
  if (tx.vin[index].type() == typeid(txin_to_key))
  {
    const txin_to_key& in = boost::get<txin_to_key>(tx.vin[index]);
    if (tx.signatures[index].type() != typeid(NLSAG_sig) || in.amount != src.amount)
      return false;
    const std::vector<crypto::signature>& sig = boost::get<NLSAG_sig>(tx.signatures[index]).s;
    if (sig.size() != src.outputs.size() || !crypto::validate_key_image(in.k_image))
      return false;
    std::vector<const crypto::public_key*> keys;
    for (const auto& o : src.outputs)
      keys.push_back(&o.stealth_address);
    return crypto::check_ring_signature(m, in.k_image, keys, sig.data());
  }
  return false;
}

// The ring of a source in the order of the transaction: by global index.
static tx_source_entry sorted(const tx_source_entry& src)
{
  tx_source_entry s = src;
  std::stable_sort(s.outputs.begin(), s.outputs.end(), [](const tx_source_entry::output_entry& a, const tx_source_entry::output_entry& b) {
    if (a.out_reference.type() == typeid(uint64_t) && b.out_reference.type() == typeid(uint64_t))
      return boost::get<uint64_t>(a.out_reference) < boost::get<uint64_t>(b.out_reference);
    return a.out_reference.type() == typeid(uint64_t) && b.out_reference.type() != typeid(uint64_t);
  });
  return s;
}

static int cmd_check(int argc, char** argv)
{
  account_keys keys = make_keys(pod<crypto::secret_key>(argv[1]), pod<crypto::secret_key>(argv[0]));
  std::string decrypted = crypto::chacha_crypt_legacy(read_file(argv[2]), keys.view_secret_key);
  finalized_tx ft{};
  if (!t_unserializable_object_from_blob(ft, decrypted))
    throw std::runtime_error("failed to parse the signed blob");
  if (t_serializable_object_to_blob(ft) != decrypted)
    throw std::runtime_error("the signed blob does not serialize back to itself");
  const transaction& tx = ft.tx;
  std::string tx_blob = t_serializable_object_to_blob(tx);
  crypto::hash tx_id = get_transaction_hash(tx);

  bool semantic = validate_tx_semantic(tx, tx_blob.size(), tx_id);
  // Each input verifies against the ring of exactly one source.
  bool inputs = tx.vin.size() == ft.ftp.sources.size() && tx.signatures.size() == tx.vin.size();
  for (size_t i = 0; inputs && i < tx.vin.size(); ++i)
  {
    size_t good = 0;
    for (const auto& src : ft.ftp.sources)
      if (check_input(tx, i, tx_id, sorted(src)))
        ++good;
    inputs = good == 1;
  }
  std::vector<zc_outs_range_proofs_with_commitments> range_proofs;
  bool range = collect_rangeproofs_data_from_tx(tx, tx_id, range_proofs) && verify_multiple_zc_outs_range_proofs(range_proofs);
  bool balance = check_tx_balance(tx, tx_id);
  bool surjection = verify_asset_surjection_proof(tx, tx_id);
  bool id = ft.tx_id == tx_id;
  crypto::public_key tx_pub{};
  bool key = crypto::secret_key_to_public_key(ft.one_time_key, tx_pub) && tx_pub == get_tx_pub_key_from_extra(tx);
  std::cout << "check tx=" << ph(tx_id) << " version=" << tx.version << " semantic=" << semantic << " inputs=" << inputs
            << " range=" << range << " balance=" << balance << " surjection=" << surjection << " id=" << id << " key=" << key
            << " fee=" << get_tx_fee(tx) << "\n";

  std::vector<account_keys> accounts{keys};
  for (int i = 3; i + 1 < argc; i += 2)
    accounts.push_back(make_keys(pod<crypto::secret_key>(argv[i + 1]), pod<crypto::secret_key>(argv[i])));
  for (size_t a = 0; a < accounts.size(); ++a)
  {
    const account_keys& who = accounts[a];
    std::vector<wallet_out_info> outs;
    crypto::key_derivation derivation{};
    bool r = lookup_acc_outs(who, tx, outs, derivation);
    std::cout << "outs " << a << " " << r;
    for (const auto& o : outs)
      std::cout << " " << o.index << ":" << o.amount << ":" << ph(o.asset_id) << ":" << o.payment_id;
    std::cout << "\n";
    std::vector<payload_items_v> items;
    decrypt_payload_items(a != 0, tx, who, items);
    std::cout << "items " << a << dump_items(items) << "\n";
  }
  bool ok = semantic && inputs && range && balance && surjection && id && key;
  std::cout << (ok ? "ACCEPTED" : "REJECTED") << " " << ph(crypto::cn_fast_hash(decrypted.data(), decrypted.size())) << "\n";
  return ok ? 0 : 1;
}

int main(int argc, char** argv)
{
  // The reference logs what fails; ZANO_HARNESS_LOG=1 shows it (on stdout).
  if (getenv("ZANO_HARNESS_LOG"))
  {
    epee::log_space::get_set_log_detalisation_level(true, LOG_LEVEL_0);
    epee::log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);
  }
  try
  {
    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "vectors")
      return cmd_vectors();
    if (cmd == "sign" && argc == 6)
      return cmd_sign(argv + 2);
    if (cmd == "check" && argc >= 5)
      return cmd_check(argc - 2, argv + 2);
    std::cerr << "usage: zano_harness vectors | sign <view> <spend> <in> <out> | check <view> <spend> <signed> [<view> <spend>]...\n";
    return 2;
  }
  catch (const std::exception& e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
