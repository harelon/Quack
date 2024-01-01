from os.path import basename
from typing import List, Any
import hashlib
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester("md5", FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.UINT, ParamType.BYTES]))

@TestWrapper(tester, [(b"asdf", 4, b""), (b"", 0, b"")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return outs[2].get_pointed(16) == hashlib.md5(params[0]).digest()

tester = RegisterTester("md5_hex", FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.UINT, ParamType.BYTES]))

@TestWrapper(tester, [(b"asdf", 4, b""), (b"", 0, b"")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return outs[2].get_pointed(32) == hashlib.md5(params[0]).hexdigest()

tester = RegisterTester("sha1", FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.UINT, ParamType.BYTES]))

@TestWrapper(tester, [(b"asdf", 4, b""), (b"", 0, b"")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return outs[2].get_pointed(20) == hashlib.sha1(params[0]).digest()

tester = RegisterTester("sha1_hex", FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.UINT, ParamType.BYTES]))

@TestWrapper(tester, [(b"asdf", 4, b""), (b"", 0, b"")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return outs[2].get_pointed(40) == hashlib.sha1(params[0]).hexdigest()
