####### PTF MODULE IMPORTS ########
import ptf
from ptf.testutils import *
####### PTF modules for BFRuntime Client Library APIs #######
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
######## PTF modules for Fixed APIs (Thrift) ######
import pd_base_tests
from ptf.thriftutils import *
from res_pd_rpc import * # Common data types
from mc_pd_rpc import * # Multicast-specific data types
from mirror_pd_rpc import * # Mirror-specific data types
####### Additional imports ########
import pdb # To debug insert pdb.set_trace() anywhere
####### Utils #######
from scapy.all import *
load_layer('tls')
import struct
import os

sid = 128
egress_port = 1

class Test01TLSOnlyTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "iotell"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # Connect to the program, running on the target
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")

        self.iotell_report = self.bfrt_info.table_get("Ingress.iotell_report")
        self.iotell_report.info.key_field_annotation_add("hdr.ssl.hs_type", "ssl")
        self.iotell_report.info.key_field_annotation_add("hdr.ssl.hs_version", "ssl")
        self.tables = [self.iotell_report]

    def runTest(self):
        print ("=== Setting up tables ===")
        self.mirror_cfg_table.entry_add(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])],
            [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                            gc.DataTuple('$ucast_egress_port', egress_port),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)],
                                        '$normal')]
        )

        key = self.iotell_report.make_key([gc.KeyTuple('hdr.ssl.hs_type', 0x01), gc.KeyTuple('hdr.ssl.hs_version', 0x0303)])
        data = self.iotell_report.make_data([gc.DataTuple('mirror_session', sid)], "Ingress.mirror_to_collector")
        self.iotell_report.entry_add(self.dev_tgt, [key], [data])

        print ("=== Loading PCAP ===")
        tls_pkts = rdpcap(os.path.join(os.path.dirname(__file__), "tls_client_hello.pcap"))
        num_pkts = len(tls_pkts)

        num_client_hello_pkts = 0
        for pkt in tls_pkts:
            if 'TLSClientHello' in pkt:
                num_client_hello_pkts = num_client_hello_pkts + 1
        print("client hellos: " + str(num_client_hello_pkts) + " others: " + str(num_pkts-num_client_hello_pkts))   

        for pkt in tls_pkts:
            send_packet(self, 0, pkt)
            pkt = struct.pack('>H', sid) / pkt
            expected_pkt = copy.deepcopy(pkt)
            verify_packet(self, expected_pkt, 1, timeout=1)

    def cleanUp(self):
        print("=== Cleaning up ===")
        self.mirror_cfg_table.entry_del(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
        )
        try:
            for t in self.tables:
                keys = []
            for (d, k) in t.entry_get(self.dev_tgt):
                if k is not None:
                    keys.append(k)
            
            t.entry_del(self.dev_tgt, keys)
            try:
                t.defaylt_entry_reset(self.dev_tgt)
            except:
                pass
            print("Tables cleaned up!")
        except Exception as e:
            print("Error cleaning up: {}".format(e))

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)

class Test02TLSMixedTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "iotell"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # Connect to the program, running on the target
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")

        self.iotell_report = self.bfrt_info.table_get("Ingress.iotell_report")
        self.iotell_report.info.key_field_annotation_add("hdr.ssl.hs_type", "ssl")
        self.iotell_report.info.key_field_annotation_add("hdr.ssl.hs_version", "ssl")
        self.tables = [self.iotell_report]

    def runTest(self):
        print ("=== Setting up tables ===")
        self.mirror_cfg_table.entry_add(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])],
            [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                            gc.DataTuple('$ucast_egress_port', egress_port),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)],
                                        '$normal')]
        )

        key = self.iotell_report.make_key([gc.KeyTuple('hdr.ssl.hs_type', 0x01), gc.KeyTuple('hdr.ssl.hs_version', 0x0303)])
        data = self.iotell_report.make_data([gc.DataTuple('mirror_session', sid)], "Ingress.mirror_to_collector")
        self.iotell_report.entry_add(self.dev_tgt, [key], [data])

        print ("=== Loading PCAP ===")
        tls_pkts = rdpcap(os.path.join(os.path.dirname(__file__), "tls_mixed.pcap"))
        num_pkts = len(tls_pkts)

        num_client_hello_pkts = 0
        for pkt in tls_pkts:
            if 'TLSClientHello' in pkt:
                num_client_hello_pkts = num_client_hello_pkts + 1
        print("client hellos: " + str(num_client_hello_pkts) + " others: " + str(num_pkts-num_client_hello_pkts))

        count_client_hello = 0
        for pkt in tls_pkts:
            send_packet(self, 0, pkt)
            if 'TLSClientHello' in pkt:
                count_client_hello = count_client_hello + 1
                pkt = struct.pack('>H', sid) / pkt
                expected_pkt = copy.deepcopy(pkt)
                verify_packet(self, expected_pkt, 1, timeout=1)
            else:
                expected_pkt = copy.deepcopy(pkt)
                verify_no_packet(self, expected_pkt, 1, timeout=1)

        assert count_client_hello == num_client_hello_pkts

    def cleanUp(self):
        print("=== Cleaning up ===")
        self.mirror_cfg_table.entry_del(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
        )
        try:
            for t in self.tables:
                keys = []
            for (d, k) in t.entry_get(self.dev_tgt):
                if k is not None:
                    keys.append(k)
            
            t.entry_del(self.dev_tgt, keys)
            try:
                t.defaylt_entry_reset(self.dev_tgt)
            except:
                pass
            print("Tables cleaned up!")
        except Exception as e:
            print("Error cleaning up: {}".format(e))

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)