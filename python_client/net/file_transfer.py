
from protocol.message_types import (
    LIST_FILES_REQUEST,
    LIST_FILES_RESPONSE,
    GET_FILE_REQUEST,
    FILE_CHUNK,
    FILE_TRANSFER_COMPLETE,
)
from protocol.serializer import json_dumps_bytes, json_loads_bytes
from files.chunker import chunk_bytes

def build_list_files_request():
    return {
        "type": LIST_FILES_REQUEST
    }

def build_list_files_response(files):
    return {
        "type": LIST_FILES_RESPONSE,
        "files": files
    }

def build_get_file_request(filename):
    return {
        "type": GET_FILE_REQUEST,
        "file": filename
    }

def stream_file_chunks(filename, file_bytes):
    for i, chunk in enumerate(chunk_bytes(file_bytes)):
        yield {
            "type": FILE_CHUNK,
            "file": filename,
            "index": i,
            "data": chunk.hex()
        }

def build_transfer_complete(filename):
    return {
        "type": FILE_TRANSFER_COMPLETE,
        "file": filename
    }
