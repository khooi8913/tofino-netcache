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
import struct
import os

session_id = 128
collector_port = 3

class Test01SimpleReadQuery(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "netcache"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # Connect to the program, running on the target
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")
        
        self.nc_cache_check = self.bfrt_info.table_get("Ingress.nc_cache_check")
        self.threshold = self.bfrt_info.table_get("Ingress.threshold")
        self.hh_report = self.bfrt_info.table_get("Ingress.hh_report")
        self.ipv4_forward = self.bfrt_info.table_get("Ingress.ipv4_forward")

        self.nc_value_reg = self.bfrt_info.table_get("Ingress.nc_value_reg")
        self.nc_valid_reg = self.bfrt_info.table_get("Ingress.nc_valid_reg")
        self.nc_hit_counter = self.bfrt_info.table_get("Ingress.nc_hit_counter")

        self.sketch0 = self.bfrt_info.table_get("Ingress.cms.sketch0")
        self.sketch1 = self.bfrt_info.table_get("Ingress.cms.sketch1")
        self.bf0 = self.bfrt_info.table_get("Ingress.bf.bf0")
        self.bf1 = self.bfrt_info.table_get("Ingress.bf.bf1")

        self.tables = [self.nc_cache_check, self.threshold, self.hh_report, self.ipv4_forward]
        self.registers = [self.nc_value_reg, self.nc_valid_reg, self.nc_hit_counter, self.sketch0, self.sketch1, self.bf0, self.bf1]

    def runTest(self):
        print ("=== Setting up tables ===")
        self.mirror_cfg_table.entry_add(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', session_id)])],
            [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                            gc.DataTuple('$ucast_egress_port', collector_port),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)],
                                        '$normal')]
        )

        key = self.hh_report.make_key([gc.KeyTuple('send_to_controller', 0x01)])
        data = self.hh_report.make_data([gc.DataTuple('mirror_session', session_id)], "Ingress.mirror_packet_to_controller_act")
        self.hh_report.entry_add(self.dev_tgt, [key], [data])


    def cleanUp(self):
        print("=== Cleaning up ===")
        self.mirror_cfg_table.entry_del(
            self.dev_tgt,
            [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', session_id)])]
        )
        try:
            for tab in self.tables:
                tab.entry_del(self.dev_tgt)
            print("Tables cleaned up!")

            for reg in self.registers:
                reg.entry_del(self.dev_tgt)
            print("Registers cleaned up!")

        except Exception as e:
            print("Error cleaning up: {}".format(e))


    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)