import hashlib
import time
import os
import json
from flask import Flask

app = Flask(__name__)

CHAINDATA_DIR = '/opt/chaindata'
NUM_ZEROS = 6


class Block():
    def __init__(self, dict):
        self.data = dict
        if not self.data.get('hash'):
            self.data['hash'] = self.create_self_hash()

    def __str__(self):
        return (f'Block<prev_hash: {self.data["prev_hash"]}'
                f',hash: {self.data["hash"]}')

    def __getattr__(self, name):
        if name in self.data:
            return self.data.get(name)
        raise AttributeError

    def self_save(self):
        index_string = str(self.data['index']).zfill(6)
        filename = f'{CHAINDATA_DIR}/{index_string}.json'
        with open(filename, 'w') as block_file:
            json.dump(self.data, block_file)

    def header_string(self):
        # https://en.bitcoin.it/wiki/Block_hashing_algorithm
        keys = ['index', 'prev_hash', 'data', 'timestamp', 'nonce']
        return "".join([str(self.data[k]) for k in keys])

    def create_self_hash(self):
        calculate_hash(self.index, self.prev_hash, self.data, self.timestamp,
                       self.nonce)


def calculate_hash(index, prev_hash, data, timestamp, nonce):
    header_string = f'{index}{prev_hash}{data}{timestamp}{nonce}'
    sha = hashlib.sha256()
    sha.update(header_string.encode('utf-8'))
    return sha.hexdigest()


def create_first_block():
    block_data = {
        'index': 0,
        'timestamp': int(time.time()),
        'data': 'First block',
        'prev_hash': '',
        'nonce': 0,
    }
    block = Block(block_data)
    return block


def sync():
    node_blocks = []
    if os.path.exists(CHAINDATA_DIR):
        for filename in os.listdir(CHAINDATA_DIR):
            if filename.endswith('.json'):
                filepath = f'{CHAINDATA_DIR}/{filename}'
                with open(filepath, 'r') as block_file:
                    block_info = json.load(block_file)
                    block_object = Block(block_info)
                    node_blocks.append(block_object)
    return node_blocks


def mine(last_block):
    index = last_block.index + 1
    timestamp = int(time.time())
    data = f"I block {last_block.index + 1}"
    prev_hash = last_block.hash
    nonce = -1

    start_time = time.time()
    block_hash = ""
    while not block_hash.startswith('0' * NUM_ZEROS):
        nonce += 1
        block_hash = calculate_hash(index, prev_hash, data, timestamp, nonce)
    print(block_hash)
    elapsed_time = time.time() - start_time
    print(elapsed_time)
    return Block({
        'index': index,
        'timestamp': timestamp,
        'data': data,
        'prev_hash': prev_hash,
        'hash': block_hash,
    })


@app.route('/blockchain.json', methods=['GET'])
def blockchain():
    print(node_blocks)
    return json.dumps([b.data for b in node_blocks])


if __name__ == '__main__':
    if os.listdir(CHAINDATA_DIR) == []:
        first_block = create_first_block()
        first_block.self_save()
    node_blocks = sync()
    new_block = mine(node_blocks[-1])
    new_block.self_save()
    app.run(debug=True, host='0.0.0.0')
