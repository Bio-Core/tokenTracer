#!/usr/bin/python

import unittest

from tokenTracer.tokenTracer import sniffFrontend 
from tokenTracer.tokenTracer import packetDict

import pyshark
import inspect

from pyshark.tshark.tshark_xml import packet_from_xml_packet as xmlToPacket

# argument parser tests

class test_arg_parse(unittest.TestCase):

    # interface option tests

    def setUp(self):
        self.sniffer = sniffFrontend()

    def test_parser_interface_short(self):
        parser = self.sniffer.argParse(['-i', 'eth0'])
        self.assertEqual(parser.interface, 'eth0')

    def test_parser_interface_null(self):
        parser = self.sniffer.argParse(None)
        self.assertEqual(parser.interface, 'eth0')

    def test_parser_interface_long(self):
        parser = self.sniffer.argParse(['--interface', 'eth0'])
        self.assertEqual(parser.interface, 'eth0')

    # all option tests

    def test_parser_all_short(self):
        parser = self.sniffer.argParse(['-a'])
        self.assertTrue(parser.allPackets)

    def test_parser_all_null(self):
        parser = self.sniffer.argParse(None)
        self.assertFalse(parser.allPackets)

    def test_parser_all_long(self):
        parser = self.sniffer.argParse(['--all'])
        self.assertTrue(parser.allPackets)

    # json format option tests

    def test_parser_json_short(self):
        parser = self.sniffer.argParse(['-j'])
        self.assertTrue(parser.jsonFormat)

    def test_parser_json_null(self):
        parser = self.sniffer.argParse(None)
        self.assertFalse(parser.jsonFormat)

    def test_parser_json_long(self):
        parser = self.sniffer.argParse(['--json'])
        self.assertTrue(parser.jsonFormat)

    # input-file option tests

    def test_parser_inputfile_short(self):
        parser = self.sniffer.argParse(['-f', 'packet.pcap'])
        self.assertEqual(parser.iFile, 'packet.pcap')

    def test_parser_inputfile_null(self):
        parser = self.sniffer.argParse(None)
        self.assertIsNone(parser.iFile)

    def test_parser_inputfile_long(self):
        parser = self.sniffer.argParse(['--file', 'packet.pcap'])
        self.assertEqual(parser.iFile, 'packet.pcap')

    def test_parser_inputfile_short_alt(self):
        parser = self.sniffer.argParse(['-f', 'input.pcap'])
        self.assertEqual(parser.iFile, 'input.pcap')

    def test_parser_inputfile_long_alt(self):
        parser = self.sniffer.argParse(['--file', 'input.pcap'])
        self.assertEqual(parser.iFile, 'input.pcap')

    def test_parser_inputfile_short_root(self):
        parser = self.sniffer.argParse(['-f', '/home/user/Documents/input.pcap'])
        self.assertEqual(parser.iFile, '/home/user/Documents/input.pcap')

    def test_parser_inputfile_long_root(self):
        parser = self.sniffer.argParse(['--file', '/home/user/Documents/input.pcap'])
        self.assertEqual(parser.iFile, '/home/user/Documents/input.pcap')

    def test_parser_inputfile_short_rel(self):
        parser = self.sniffer.argParse(['-f', 'tokenTracer/input.pcap'])
        self.assertEqual(parser.iFile, 'tokenTracer/input.pcap')

    def test_parser_inputfile_long_rel(self):
        parser = self.sniffer.argParse(['--file', 'tokenTracer/input.pcap'])
        self.assertEqual(parser.iFile, 'tokenTracer/input.pcap')


class test_packet_dict_empty(unittest.TestCase):
    
    # packetDict tests

    def setUp(self):
        self.pDict = packetDict(False, False)

    def test_pdict_printall(self):
        self.assertFalse(self.pDict.printAll)

    def test_pdict_json(self):
        self.assertFalse(self.pDict.json)

    # data dictionary tests

    def test_pdict_data_instance(self):
        self.assertIsInstance(self.pDict.data, dict)

    def test_pdict_data_keyerror(self):
        with self.assertRaises(KeyError):
            self.pDict.data["fieldName"]

    def test_pdict_data_dict_equal(self):
        self.assertDictEqual(self.pDict.data, dict())

    # data dictionary tests
    def test_pdict_request(self):
        self.assertTrue(self.pDict.request)

    def test_pdict_refreshrequest(self):
        self.assertTrue(self.pDict.refreshRequest)

    def test_pdict_response(self):
        self.assertTrue(self.pDict.response)

    def test_pdict_http(self):
        self.assertTrue(self.pDict.http)

    def test_pdict_httpdata(self):
        self.assertTrue(self.pDict.httpData)

    def test_pdict_httpjson(self):
        self.assertTrue(self.pDict.httpJson)


# tests for clearing the empty dict

class test_packet_dict_empty_clear(test_packet_dict_empty):
    
    # packetDict tests

    def setUp(self):
        self.pDict = packetDict(False, False)
        self.pDict.clearData()


# tests for loading the empty packet

class test_packet_dict_load_packet_empty(test_packet_dict_empty):
    
    # packetDict tests

    def setUp(self):
        self.pDict = packetDict(False, False)
        self.packet = pyshark.packet.packet.Packet()
        self.pDict.loadAll(self.packet)

    def test_pdict_http(self):
        self.assertFalse(self.pDict.http)


# test for loading a null object

class test_packet_dict_load_null(test_packet_dict_empty):
    
    # packetDict tests

    def setUp(self):
        self.pDict = packetDict(False, False)
        self.pDict.loadAll(None)

# load a packet with empty layers

class test_packet_http_header(test_packet_dict_empty):
    
    def packetFileLoad(self, packetFile):
        self.pDict = packetDict(False, False)
        testFileName = packetFile
        testFile = open(testFileName, "r")
        packetStr = testFile.read()
        testFile.close()
        self.packet = xmlToPacket(packetStr)
        self.pDict.loadAll(self.packet)

    def setUp(self):
        testFileName = 'testHttp1.pdml'
        self.packetFileLoad(testFileName)


class test_packet_emptyLayer(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'test1.pdml'
        self.packetFileLoad(testFileName)

    def test_pdict_http(self):
        self.assertFalse(self.pDict.http)


class test_packet_http_headerless(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'testHttp2.pdml'
        self.packetFileLoad(testFileName)


class test_packet_http_header_src_dst(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'testHttp3.pdml'
        self.packetFileLoad(testFileName)
        

class test_packet_http_header_src_dst_srcport(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'testHttp4.pdml'
        self.packetFileLoad(testFileName)


class test_packet_http_header_src_dst_ports(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'testHttp5.pdml'
        self.packetFileLoad(testFileName)

class test_packet_http_head_src_dst_ports_time(test_packet_http_header):
    
     # packetDict tests

    def setUp(self):
        testFileName = 'testHttp6.pdml'
        self.packetFileLoad(testFileName)


    def test_pdict_httpdata(self):
        self.assertFalse(self.pDict.httpData)


    def test_pdict_data_dict_equal(self):
        dictComp = { 'HTTP Header': 'HTTP/1.1 OK\\r\\n',
                     'destIP': '172.0.0.1',
                     'destPort': '80',
                     'packetSize': 'None',
                     'sourceIP': '172.0.0.1',
                     'sourcePort': '80',
                     'timestamp': '1969-12-31 19:00:01'
                   }
        self.assertDictEqual(self.pDict.data, dictComp)


class test_packet_http_data(test_packet_http_header):
    
    def setUp(self):
        testFileName = 'testHttp7.pdml'
        self.packetFileLoad(testFileName)

    def test_pdict_httpjson(self):
        self.assertFalse(self.pDict.httpJson)

    def test_pdict_request(self):
        self.assertFalse(self.pDict.request)

    def test_pdict_data_dict_equal(self):
        dictComp = { 'HTTP Header': 'HTTP/1.1 OK\\r\\n',
                     'destIP': '172.0.0.1',
                     'destPort': '80',
                     'packetSize': 'None',
                     'sourceIP': '172.0.0.1',
                     'sourcePort': '80',
                     'timestamp': '1969-12-31 19:00:01'
                   }
        self.assertDictEqual(self.pDict.data, dictComp)

class test_packet_http_data(test_packet_http_data):
    
    def setUp(self):
        testFileName = 'testHttp8.pdml'
        self.packetFileLoad(testFileName)

class test_packet_http_data(test_packet_http_data):
    
    def setUp(self):
        testFileName = 'testHttp9.pdml'
        self.packetFileLoad(testFileName)

class test_packet_http_data(test_packet_http_data):
    
    def setUp(self):
        testFileName = 'testHttp10.pdml'
        self.packetFileLoad(testFileName)





if __name__ == "__main__":
    unittest.main()
