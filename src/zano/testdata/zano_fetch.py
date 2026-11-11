#!/usr/bin/env python3
"""Dumps blocks, transactions and rings of a Zano daemon into a directory
the ignored tools of `src/zano/tests/chain.rs` read (`ZANO_TX_DIR`).

    ZANO_RPC=https://host/json_rpc python3 zano_fetch.py DIR blocks START:COUNT [START:COUNT ...]
    ZANO_RPC=... python3 zano_fetch.py DIR tx TXID [TXID ...]
    ZANO_RPC=... python3 zano_fetch.py DIR assets
    ZANO_RPC=... python3 zano_fetch.py DIR decoys COUNT
    ZANO_RPC=... python3 zano_fetch.py DIR template ADDRESS
    ZANO_RPC=... python3 zano_fetch.py DIR ask

Only read-only JSON-RPC methods are called (get_blocks_details,
get_tx_details, get_out_info, getrandom_outs3, get_assets_list, getinfo,
getblocktemplate, and for `ask` decrypt_tx_details and validate_signature),
one at a time and at most four a second. Nothing is ever
broadcast.

What it writes:

  blocks.jsonl     one line per block: height, id, type (0 PoS, 1 PoW),
                   timestamp, difficulty, base_reward, total_fee, size (the
                   cumulative size the reward depends on), median (of the
                   sizes of the 400 blocks before, for blocks over 125000
                   bytes only), blob (the block as it is serialized, put
                   together from its header, its first transaction and the
                   ids of the others), txs (ids, the first transaction of
                   the block first)
  <txid>.hex       the transaction
  <txid>.rings     for each input with a ring, its members:
                   `input stealth concealing commitment asset global_index`
  <txid>.gidx      the global index of each output
  assets.jsonl     the asset descriptors the daemon has now
  random_outs.json a raw getrandom_outs3 response (decoys)
  info.json        height and the number of confidential outputs
  template.hex     a block template for ADDRESS, with template.json: what
                   the daemon says of it (the amounts and blinding masks of
                   its outputs among it)
  ask_*.json.reply the daemon's answers to the questions `tool_daemon_requests`
                   wrote as ask_*.json
"""
import base64
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

URL = os.environ.get("ZANO_RPC", "")
DELAY = 0.2
_last = [0.0]


def call_raw(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": method, "params": params})
    wait = DELAY - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    request = urllib.request.Request(
        URL, data=body.encode(), headers={"content-type": "application/json", "user-agent": "curl/8"}
    )
    for attempt in range(4):
        try:
            data = urllib.request.urlopen(request, timeout=180).read()
            break
        except urllib.error.HTTPError as e:
            data = e.read()
            break
        except Exception:  # a network hiccup: wait and try again
            if attempt == 3:
                raise
            time.sleep(3 * (attempt + 1))
    _last[0] = time.time()
    return data


def call(method, params):
    # The daemon writes binary strings raw: keep the bytes through the decoding.
    text = call_raw(method, params).decode("utf-8", "surrogateescape")
    reply = json.loads(text)
    return reply.get("result")


def binary(text):
    """The bytes of a binary string of a daemon reply."""
    return text.encode("utf-8", "surrogateescape")


def varint(n):
    out = b""
    while n >= 0x80:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    return out + bytes([n])


class Dump:
    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self.outs = {}
        self.outs_path = os.path.join(path, "outs.cache")
        if os.path.exists(self.outs_path):
            for line in open(self.outs_path):
                key, value = line.split(None, 1)
                self.outs[key] = value.strip()
        self.known_blocks = set()
        blocks = os.path.join(path, "blocks.jsonl")
        if os.path.exists(blocks):
            for line in open(blocks):
                self.known_blocks.add(json.loads(line)["height"])

    def file(self, name):
        return os.path.join(self.path, name)

    def remember(self, key, value):
        self.outs[key] = value
        with open(self.outs_path, "a") as f:
            f.write(f"{key} {value}\n")

    # --- transactions ---

    def tx_info(self, txid):
        result = call("get_tx_details", {"tx_hash": txid})
        if not result or "tx_info" not in result:
            return None
        return result["tx_info"]

    def out_keys(self, amount, index):
        """An output by its global index: stealth concealing commitment asset."""
        key = f"{amount}:{index}"
        if key in self.outs:
            return self.outs[key]
        where = call("get_out_info", {"amount": amount, "i": index})
        if not where or where.get("status") != "OK":
            return None
        info = self.tx_info(where["tx_id"])
        if info is None:
            return None
        # Every output of that transaction is worth remembering.
        found = None
        for n, out in enumerate(info["outs"]):
            keys = out["pub_keys"]
            if out["amount"] != 0:
                value = f"{keys[0]} {'0' * 64} {'0' * 64} {'0' * 64}" if keys else None
            else:
                value = " ".join(keys[:4]) if len(keys) >= 4 else None
            if value is None or len(keys[0]) != 64:
                continue
            self.remember(f"{out['amount']}:{out['global_index']}", value)
            if n == where["out_no"]:
                found = value
        return found

    def random_outs(self, indices):
        """Confidential outputs by global index, in one request."""
        result = call(
            "getrandom_outs3",
            {
                "amounts": [{"amount": 0, "global_offsets": indices}],
                "height_upper_limit": 0,
                "use_forced_mix_outs": False,
                "coinbase_percents": 15,
            },
        )
        if not result or result.get("status") != "OK":
            return
        blob = binary(result["outs"][0]["outs"])
        if len(blob) != 144 * len(indices):
            return
        for n, index in enumerate(indices):
            entry = blob[144 * n : 144 * n + 144]
            flags = int.from_bytes(entry[136:], "little")
            if flags & 2 or int.from_bytes(entry[:8], "little") != index:
                continue
            keys = [entry[8 + 32 * k : 40 + 32 * k].hex() for k in range(4)]
            self.remember(f"0:{index}", " ".join(keys))

    def save_tx(self, txid, rings=True):
        hex_path = self.file(f"{txid}.hex")
        rings_path = self.file(f"{txid}.rings")
        if os.path.exists(hex_path) and (not rings or os.path.exists(rings_path)):
            return True
        info = self.tx_info(txid)
        if info is None:
            print(f"transaction {txid} not found", file=sys.stderr)
            return False
        with open(hex_path, "w") as f:
            f.write(base64.b64decode(info["blob"]).hex() + "\n")
        with open(self.file(f"{txid}.gidx"), "w") as f:
            f.write(" ".join(str(out.get("global_index", 0)) for out in info["outs"]) + "\n")
        if not rings:
            return True
        wanted = [i for i in info["ins"] if i.get("global_indexes")]
        missing = [
            index
            for i in wanted
            if i["amount"] == 0
            for index in i["global_indexes"]
            if f"0:{index}" not in self.outs
        ]
        for start in range(0, len(missing), 256):
            self.random_outs(missing[start : start + 256])
        lines = []
        for n, i in enumerate(info["ins"]):
            for index in i.get("global_indexes") or []:
                keys = self.out_keys(i["amount"], index)
                if keys is None:
                    print(f"{txid}: output {i['amount']}:{index} not found", file=sys.stderr)
                    return False
                lines.append(f"{n} {keys} {index}")
        with open(rings_path, "w") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
        return True

    # --- blocks ---

    def block_details(self, start, count):
        result = call("get_blocks_details", {"height_start": start, "count": count, "ignore_transactions": False})
        return result["blocks"] if result else []

    def median_before(self, height):
        sizes = []
        start = max(0, height - 400)
        while start < height:
            count = min(100, height - start)
            sizes += [b["block_cumulative_size"] for b in self.block_details(start, count)]
            start += count
        sizes.sort()
        if not sizes:
            return 0
        half = len(sizes) // 2
        return sizes[half] if len(sizes) % 2 else (sizes[half - 1] + sizes[half]) // 2

    def save_blocks(self, start, count, rings=True):
        end = start + count
        while start < end:
            step = min(20, end - start)
            for block in self.block_details(start, step):
                if block["height"] in self.known_blocks:
                    continue
                self.save_block(block, rings)
            start += step

    def save_block(self, block, rings):
        described = json.loads(block["object_in_json"])
        header = described["AGGREGATED"]
        txs = [tx["id"] for tx in block["transactions_details"]]
        if txs[1:] != described["tx_hashes"]:
            print(f"block {block['height']}: transaction lists differ", file=sys.stderr)
        ok = True
        for txid in txs:
            ok &= self.save_tx(txid, rings)
        if not os.path.exists(self.file(f"{txs[0]}.hex")):
            return
        miner = bytes.fromhex(open(self.file(f"{txs[0]}.hex")).read().strip())
        blob = (
            bytes([header["major_version"]])
            + header["nonce"].to_bytes(8, "little")
            + bytes.fromhex(header["prev_id"])
            + varint(header["minor_version"])
            + varint(header["timestamp"])
            + bytes([header["flags"]])
            + miner
            + varint(len(txs) - 1)
            + b"".join(bytes.fromhex(t) for t in txs[1:])
        )
        line = {
            "height": block["height"],
            "id": block["id"],
            "type": block["type"],
            "timestamp": block["timestamp"],
            "difficulty": block["difficulty"],
            "base_reward": block["base_reward"],
            "total_fee": block["total_fee"],
            "size": block["block_cumulative_size"],
            "blob": blob.hex(),
            "txs": txs,
            "complete": bool(ok),
        }
        if block["block_cumulative_size"] > 125000:
            line["median"] = self.median_before(block["height"])
        with open(self.file("blocks.jsonl"), "a") as f:
            f.write(json.dumps(line) + "\n")
        self.known_blocks.add(block["height"])

    # --- the rest ---

    def save_assets(self):
        offset = 0
        with open(self.file("assets.jsonl"), "w") as f:
            while True:
                result = call("get_assets_list", {"offset": offset, "count": 100})
                assets = (result or {}).get("assets") or []
                for asset in assets:
                    f.write(json.dumps(asset) + "\n")
                offset += len(assets)
                if len(assets) < 100:
                    break
        print(f"{offset} assets")

    def save_info(self):
        info = call("getinfo", {"flags": 0})
        top = self.block_details(info["height"] - 1, 1)[0]
        last = self.tx_info(top["transactions_details"][0]["id"])
        outs = max(out["global_index"] for out in last["outs"]) + 1
        with open(self.file("info.json"), "w") as f:
            json.dump({"height": info["height"], "zc_outputs": outs}, f)
        return info["height"], outs

    def save_decoys(self, count):
        """Candidates for the rings of a transfer: outputs spread over the
        chain, half of them among the most recent."""
        _, outs = self.save_info()
        # Outputs of the last ten blocks are still locked.
        limit = max(1, outs - 64)
        picked = set()
        while len(picked) < min(count, limit):
            if random.random() < 0.5:
                picked.add(random.randrange(max(0, limit - 20000), limit))
            else:
                picked.add(random.randrange(limit))
        raw = call_raw(
            "getrandom_outs3",
            {
                "amounts": [{"amount": 0, "global_offsets": sorted(picked)}],
                "height_upper_limit": 0,
                "use_forced_mix_outs": False,
                "coinbase_percents": 15,
            },
        )
        with open(self.file("random_outs.json"), "wb") as f:
            f.write(raw)
        print(f"{len(picked)} candidates asked, {len(raw)} bytes")

    def save_template(self, address):
        result = call("getblocktemplate", {"wallet_address": address, "extra_text": "", "pos_block": False})
        if not result or "blocktemplate_blob" not in result:
            print(f"no template: {result}", file=sys.stderr)
            return
        with open(self.file("template.hex"), "w") as f:
            f.write(result["blocktemplate_blob"] + "\n")
        with open(self.file("template.json"), "w") as f:
            json.dump({k: v for k, v in result.items() if k != "blocktemplate_blob"}, f)


def main():
    if len(sys.argv) < 3 or not URL:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    dump = Dump(sys.argv[1])
    command, args = sys.argv[2], sys.argv[3:]
    if command == "blocks":
        for spec in args:
            start, count = spec.split(":")
            dump.save_blocks(int(start), int(count))
    elif command == "tx":
        for txid in args:
            dump.save_tx(txid)
    elif command == "assets":
        dump.save_assets()
    elif command == "decoys":
        dump.save_decoys(int(args[0]))
    elif command == "template":
        dump.save_template(args[0])
    elif command == "ask":
        # The questions `tool_daemon_requests` wrote: read-only methods only.
        for name in sorted(os.listdir(dump.path)):
            if not (name.startswith("ask_") and name.endswith(".json")):
                continue
            question = json.load(open(dump.file(name)))
            if question["method"] not in ("decrypt_tx_details", "validate_signature"):
                print(f"{name}: not asked", file=sys.stderr)
                continue
            with open(dump.file(name + ".reply"), "wb") as f:
                f.write(call_raw(question["method"], question["params"]))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
