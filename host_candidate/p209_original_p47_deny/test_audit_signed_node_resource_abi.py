#!/usr/bin/env python3
"""No-APK synthetic negatives for P209 signed-only resource/ABI audit."""
import unittest
from audit_signed_node_resource_abi import (
    Denied,apk_inventory,elf_abi,direct_sites,
    linked_method_candidates,method_shape,
)

BOOT="Lcom/dsh/android/termux/TermuxBootstrap;"
class Info:
    def __init__(self,name,size=10):
        self.filename,self.file_size=name,size
    def is_dir(self):return self.filename.endswith("/")
class Ins:
    def __init__(self,op="nop",out=""):
        self.op,self.out=op,out
    def get_name(self):return self.op
    def get_output(self):return self.out
class Method:
    def __init__(self,name="nodeIsUsable",descriptor="()Z",rows=None,enabled=True):
        self.name,self.descriptor,self.rows,self.enabled=name,descriptor,rows or [],enabled
    def get_name(self):return self.name
    def get_descriptor(self):return self.descriptor
    def get_code(self):return self if self.enabled else None
    def get_instructions_idx(self):return self.rows
    def get_tries(self):return []
class Cls:
    def __init__(self,methods=None):self.methods=methods or []
    def get_name(self):return BOOT
    def get_methods(self):return self.methods
class Dex:
    def __init__(self,methods=None):self.methods=methods or []
    def get_classes(self):return [Cls(self.methods)]

class AbiTests(unittest.TestCase):
    def test_file_hints_not_equivalent_to_elf(self):
        infos=[Info("assets/node-runtime.tar.gz",900),
               Info("lib/arm64-v8a/libsomething.so",400),
               Info("assets/other.txt"),
               Info("assets/folder/")]
        total,top,abis,nodes,archives=apk_inventory(infos)
        self.assertEqual((total,top["assets"],top["lib"],archives),(3,2,1,1))
        self.assertEqual(len(nodes),1)
        self.assertEqual(abis["arm64-v8a"],1)
    def test_node_like_other_name_is_not_a_payload_hint(self):
        _,_,_,nodes,archives=apk_inventory([
            Info("assets/unrelatedNodefoo.bin"),
            Info("assets/nodejs_v1.zip")])
        self.assertEqual((len(nodes),archives),(1,1))
    def test_architecture_marker_not_an_elf_claim(self):
        self.assertEqual(elf_abi(b"arm64-v8a"),"NO_DIRECT_ELF_HEADER")
    def test_elf_machine_from_header_not_filename(self):
        value=bytearray(20);value[:4]=b"\x7fELF";value[5]=1
        value[18:20]=(183).to_bytes(2,"little")
        self.assertEqual(elf_abi(bytes(value)),"ARM64_ELF")
        value[18:20]=(62).to_bytes(2,"little")
        self.assertEqual(elf_abi(bytes(value)),"X86_64_ELF")
    def test_elf_wrong_endian_denied_as_candidate(self):
        value=bytearray(20);value[:4]=b"\x7fELF";value[5]=3
        self.assertEqual(elf_abi(bytes(value)),"UNRECOGNIZED_ELF_ENDIAN")
    def test_direct_asset_owner_vs_descriptor_reference(self):
        rows=[
            (0,Ins("invoke-virtual","v0, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;")),
            (6,Ins("invoke-virtual","v0, Lcom/example/Other;->accept(Ljava/io/File;)V")),
            (12,Ins("sget-object","v0, Landroid/os/Build;->SUPPORTED_ABIS:[Ljava/lang/String;")),
        ]
        counts,sites=direct_sites(rows)
        self.assertEqual(counts["DIRECT_ASSET_MANAGER_CALL"],1)
        self.assertEqual(counts["DIRECT_ABI_FIELD_READ"],1)
        self.assertEqual(len(sites),2)
    def test_direct_process_builder_start_flagged(self):
        counts,sites=direct_sites([(0,Ins("invoke-virtual",
            "v0, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"))])
        self.assertEqual(counts["DIRECT_PROCESS_BUILDER_START"],1)
    def test_linked_unique_signature_and_real_invoke(self):
        m=Method()
        dexes=[("classes.dex",Dex([m]))]
        rows=[(20,Ins("invoke-direct",BOOT+"->nodeIsUsable()Z"))]
        self.assertEqual(linked_method_candidates(dexes,rows,"nodeIsUsable")[2],[20])
    def test_name_without_invocation_not_a_link(self):
        m=Method()
        dexes=[("classes.dex",Dex([m]))]
        with self.assertRaises(Denied):
            linked_method_candidates(dexes,
                [(20,Ins("const-string",BOOT+"->nodeIsUsable()Z"))],
                "nodeIsUsable")
    def test_overloaded_two_invoked_methods_not_unique(self):
        a=Method(descriptor="()Z")
        b=Method(descriptor="(Ljava/io/File;)Z")
        rows=[(20,Ins("invoke-virtual",BOOT+"->nodeIsUsable()Z")),
              (26,Ins("invoke-virtual",BOOT+"->nodeIsUsable(Ljava/io/File;)Z"))]
        with self.assertRaises(Denied):
            linked_method_candidates([("classes.dex",Dex([a,b]))],
                                     rows,"nodeIsUsable")
    def test_method_shape_explicit_no_code_denied(self):
        with self.assertRaises(Exception):
            method_shape(Method(enabled=False))
    def test_method_shape_with_return(self):
        m=Method(rows=[(0,Ins("return","v0"))])
        rows,nreturns,nbranches,ntries,counts,sites=method_shape(m)
        self.assertEqual((len(rows),nreturns,nbranches,ntries),(1,1,0,0))

if __name__=="__main__":unittest.main(verbosity=2)
