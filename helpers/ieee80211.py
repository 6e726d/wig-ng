#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wig-ng - Wireless Information Gathering New Generation
# Copyright (C) 2022 - Andrés Blanco (6e726d) <6e726d@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from impacket import dot11


FRAME_CONTROL_HEADER_LENGTH = 2

TYPE_MGMT = 0b00
TYPE_CTRL = 0b01
TYPE_DATA = 0b10

TYPE_MGMT_SUBTYPE_ASSOCIATION_REQUEST = 0b0000
TYPE_MGMT_SUBTYPE_ASSOCIATION_RESPONSE = 0b0001
TYPE_MGMT_SUBTYPE_REASSOCIATION_REQUEST = 0b0010
TYPE_MGMT_SUBTYPE_REASSOCIATION_RESPONSE = 0b0011
TYPE_MGMT_SUBTYPE_PROBE_REQUEST = 0b0100
TYPE_MGMT_SUBTYPE_PROBE_RESPONSE = 0b0101
TYPE_MGMT_SUBTYPE_BEACON = 0b1000
TYPE_MGMT_SUBTYPE_ATIM = 0b1001
TYPE_MGMT_SUBTYPE_DISASSOCIATION = 0b1010
TYPE_MGMT_SUBTYPE_AUTHENTICATION = 0b1011
TYPE_MGMT_SUBTYPE_DEAUTHENTICATION = 0b1100
TYPE_MGMT_SUBTYPE_ACTION = 0b1101
TYPE_MGMT_SUBTYPE_ACTION_NO_ACK = 0b1110

# TAG IDs 
# https://raw.githubusercontent.com/
# wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
TAG_SSID = 0
TAG_SUPP_RATES = 1
TAG_FH_PARAMETER = 2
TAG_DS_PARAMETER = 3
TAG_CF_PARAMETER = 4
TAG_TIM = 5
TAG_IBSS_PARAMETER = 6
TAG_COUNTRY_INFO = 7
TAG_FH_HOPPING_PARAMETER = 8
TAG_FH_HOPPING_TABLE = 9
TAG_REQUEST = 10
TAG_QBSS_LOAD = 11
TAG_EDCA_PARAM_SET = 12
TAG_TSPEC = 13
TAG_TCLAS = 14
TAG_SCHEDULE = 15
TAG_CHALLENGE_TEXT = 16
TAG_POWER_CONSTRAINT = 32
TAG_POWER_CAPABILITY = 33
TAG_TPC_REQUEST = 34
TAG_TPC_REPORT = 35
TAG_SUPPORTED_CHANNELS = 36
TAG_CHANNEL_SWITCH_ANN = 37
TAG_MEASURE_REQ = 38
TAG_MEASURE_REP = 39
TAG_QUIET = 40
TAG_IBSS_DFS = 41
TAG_ERP_INFO = 42
TAG_TS_DELAY = 43
TAG_TCLAS_PROCESS = 44
TAG_HT_CAPABILITY = 45
TAG_QOS_CAPABILITY = 46
TAG_ERP_INFO_OLD = 47
TAG_RSN_IE = 48
TAG_EXT_SUPP_RATES = 50
TAG_AP_CHANNEL_REPORT = 51
TAG_NEIGHBOR_REPORT = 52
TAG_RCPI = 53
TAG_MOBILITY_DOMAIN = 54
TAG_FAST_BSS_TRANSITION = 55
TAG_TIMEOUT_INTERVAL = 56
TAG_RIC_DATA = 57
TAG_DSE_REG_LOCATION = 58
TAG_SUPPORTED_OPERATING_CLASSES = 59
TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT = 60
TAG_HT_INFO = 61
TAG_SECONDARY_CHANNEL_OFFSET = 62
TAG_BSS_AVG_ACCESS_DELAY = 63
TAG_ANTENNA = 64
TAG_RSNI = 65
TAG_MEASURE_PILOT_TRANS = 66
TAG_BSS_AVB_ADM_CAPACITY = 67
TAG_IE_68_CONFLICT = 68
TAG_WAPI_PARAM_SET = 68
TAG_BSS_AC_ACCESS_DELAY = 68
TAG_TIME_ADV = 69
TAG_RM_ENABLED_CAPABILITY = 70
TAG_MULTIPLE_BSSID = 71
TAG_20_40_BSS_CO_EX = 72
TAG_20_40_BSS_INTOL_CH_REP = 73
TAG_OVERLAP_BSS_SCAN_PAR = 74
TAG_RIC_DESCRIPTOR = 75
TAG_MMIE = 76
TAG_EVENT_REQUEST = 78
TAG_EVENT_REPORT = 79
TAG_DIAGNOSTIC_REQUEST = 80
TAG_DIAGNOSTIC_REPORT = 81
TAG_LOCATION_PARAMETERS = 82
TAG_NO_BSSID_CAPABILITY = 83
TAG_SSID_LIST = 84
TAG_MULTIPLE_BSSID_INDEX = 85
TAG_FMS_DESCRIPTOR = 86
TAG_FMS_REQUEST = 87
TAG_FMS_RESPONSE = 88
TAG_QOS_TRAFFIC_CAPABILITY = 89
TAG_BSS_MAX_IDLE_PERIOD = 90
TAG_TFS_REQUEST = 91
TAG_TFS_RESPONSE = 92
TAG_WNM_SLEEP_MODE = 93
TAG_TIM_BROADCAST_REQUEST = 94
TAG_TIM_BROADCAST_RESPONSE = 95
TAG_COLLOCATED_INTER_REPORT = 96
TAG_CHANNEL_USAGE = 97
TAG_TIME_ZONE = 98
TAG_DMS_REQUEST = 99
TAG_DMS_RESPONSE = 100
TAG_LINK_IDENTIFIER = 101
TAG_WAKEUP_SCHEDULE = 102
TAG_CHANNEL_SWITCH_TIMING = 104
TAG_PTI_CONTROL = 105
TAG_PU_BUFFER_STATUS = 106
TAG_INTERWORKING = 107
TAG_ADVERTISEMENT_PROTOCOL = 108
TAG_EXPIDITED_BANDWIDTH_REQ = 109
TAG_QOS_MAP_SET = 110
TAG_ROAMING_CONSORTIUM = 111
TAG_EMERGENCY_ALERT_ID = 112
TAG_MESH_CONFIGURATION = 113
TAG_MESH_ID = 114
TAG_MESH_LINK_METRIC_REPORT = 115
TAG_CONGESTION_NOTIFICATION = 116
TAG_MESH_PEERING_MGMT = 117
TAG_MESH_CHANNEL_SWITCH = 118
TAG_MESH_AWAKE_WINDOW = 119
TAG_BEACON_TIMING = 120
TAG_MCCAOP_SETUP_REQUEST = 121
TAG_MCCAOP_SETUP_REPLY = 122
TAG_MCCAOP_ADVERTISEMENT = 123
TAG_MCCAOP_TEARDOWN = 124
TAG_GANN = 125
TAG_RANN = 126
TAG_EXTENDED_CAPABILITIES = 127
TAG_AGERE_PROPRIETARY = 128
TAG_MESH_PREQ = 130
TAG_MESH_PREP = 131
TAG_MESH_PERR = 132
TAG_CISCO_CCX1_CKIP = 133
TAG_CISCO_CCX2 = 136
TAG_PXU = 137
TAG_PXUC = 138
TAG_AUTH_MESH_PEERING_EXCH = 139
TAG_MIC = 140
TAG_DESTINATION_URI = 141
TAG_U_APSD_COEX = 142
TAG_WAKEUP_SCHEDULE_AD = 143
TAG_EXTENDED_SCHEDULE = 144
TAG_STA_AVAILABILITY = 145
TAG_DMG_TSPEC = 146
TAG_NEXT_DMG_ATI = 147
TAG_DMG_CAPABILITIES = 148
TAG_CISCO_CCX3 = 149
TAG_CISCO_VENDOR_SPECIFIC = 150
TAG_DMG_OPERATION = 151
TAG_DMG_BSS_PARAMETER_CHANGE = 152
TAG_DMG_BEAM_REFINEMENT = 153
TAG_CHANNEL_MEASURMENT_FB = 154
TAG_AWAKE_WINDOW = 157
TAG_MULTI_BAND = 158
TAG_ADDBA_EXT = 159
TAG_NEXTPCP_LIST = 160
TAG_PCP_HANDOVER = 161
TAG_DMG_LINK_MARGIN = 162
TAG_SWITCHING_STREAM = 163
TAG_SESSION_TRANSMISSION = 164
TAG_DYN_TONE_PAIR_REP = 165
TAG_CLUSTER_REP = 166
TAG_RELAY_CAPABILITIES = 167
TAG_RELAY_TRANSFER_PARAM = 168
TAG_BEAMLINK_MAINTENANCE = 169
TAG_MULTIPLE_MAC_SUBLAYERS = 170
TAG_U_PID = 171
TAG_DMG_LINK_ADAPTION_ACK = 172
TAG_SYMBOL_PROPRIETARY = 173
TAG_MCCAOP_ADVERTISEMENT_OV = 174
TAG_QUIET_PERIOD_REQ = 175
TAG_QUIET_PERIOD_RES = 177
TAG_ECAPC_POLICY = 182
TAG_CLUSTER_TIME_OFFSET = 183
TAG_ANTENNA_SECTOR_ID = 190
TAG_VHT_CAPABILITY = 191
TAG_VHT_OPERATION = 192
TAG_EXT_BSS_LOAD = 193
TAG_WIDE_BW_CHANNEL_SWITCH = 194
TAG_VHT_TX_PWR_ENVELOPE = 195
TAG_CHANNEL_SWITCH_WRAPPER = 196
TAG_OPERATING_MODE_NOTIFICATION = 199
TAG_FINE_TIME_MEASUREMENT_PARAM = 206
TAG_S1G_OPEN_LOOP_LINK_MARGIN_INDEX = 207
TAG_RPS = 208
TAG_PAGE_SLICE = 209
TAG_AID_REQUEST = 210
TAG_AID_RESPONSE = 211
TAG_S1G_SECTOR_OPERATION = 212
TAG_S1G_BEACON_COMPATIBILITY = 213
TAG_SHORT_BEACON_INTERVAL = 214
TAG_CHANGE_SEQUENCE = 215
TAG_TWT = 216
TAG_S1G_CAPABILITIES = 217
TAG_SUBCHANNEL_SELECTIVE_TRANSMISSION = 220
TAG_VENDOR_SPECIFIC_IE = 221
TAG_AUTHENTICATION_CONTROL = 222
TAG_TSF_TIMER_ACCURACY = 223
TAG_S1G_RELAY = 224
TAG_REACHABLE_ADDRESS = 225
TAG_S1G_RELAY_DISCOVERY = 226
TAG_AID_ANNOUNCEMENT = 228
TAG_PV1_PROBE_RESPONSE_OPTION = 229
TAG_EL_OPERATION = 230
TAG_SECTORIZED_GROUP_ID_LIST = 231
TAG_S1G_OPERATION = 232
TAG_HEADER_COMPRESSION = 233
TAG_SST_OPERATION = 234
TAG_MAD = 235
TAG_S1G_RELAY_ACTIVATION = 236
TAG_CAG_NUMBER = 237
TAG_AP_CSN = 239
TAG_FILS_INDICATION = 240
TAG_DIFF_INITIAL_LINK_SETUP = 241
TAG_FRAGMENT = 242
TAG_ELEMENT_ID_EXTENSION = 255

tag_strings = {
    TAG_SSID: "SSID parameter set",
    TAG_SUPP_RATES: "Supported Rates",
    TAG_FH_PARAMETER: "FH Parameter set",
    TAG_DS_PARAMETER: "DS Parameter set",
    TAG_CF_PARAMETER: "CF Parameter set",
    TAG_TIM: "Traffic Indication Map (TIM)",
    TAG_IBSS_PARAMETER: "IBSS Parameter set",
    TAG_COUNTRY_INFO: "Country Information",
    TAG_FH_HOPPING_PARAMETER: "Hopping Pattern Parameters",
    TAG_FH_HOPPING_TABLE: "Hopping Pattern Table",
    TAG_REQUEST: "Request",
    TAG_QBSS_LOAD: "QBSS Load Element",
    TAG_EDCA_PARAM_SET: "EDCA Parameter Set",
    TAG_TSPEC: "Traffic Specification",
    TAG_TCLAS: "Traffic Classification",
    TAG_SCHEDULE: "Schedule",
    TAG_CHALLENGE_TEXT: "Challenge text",
    TAG_POWER_CONSTRAINT: "Power Constraint",
    TAG_POWER_CAPABILITY: "Power Capability",
    TAG_TPC_REQUEST: "TPC Request",
    TAG_TPC_REPORT: "TPC Report",
    TAG_SUPPORTED_CHANNELS: "Supported Channels",
    TAG_CHANNEL_SWITCH_ANN: "Channel Switch Announcement",
    TAG_MEASURE_REQ: "Measurement Request",
    TAG_MEASURE_REP: "Measurement Report",
    TAG_QUIET: "Quiet",
    TAG_IBSS_DFS: "IBSS DFS",
    TAG_ERP_INFO: "ERP Information",
    TAG_TS_DELAY: "TS Delay",
    TAG_TCLAS_PROCESS: "TCLAS Processing",
    TAG_HT_CAPABILITY: "HT Capabilities (802.11n D1.10)",
    TAG_QOS_CAPABILITY: "QoS Capability",
    TAG_ERP_INFO_OLD: "ERP Information",
    TAG_RSN_IE: "RSN Information",
    TAG_EXT_SUPP_RATES: "Extended Supported Rates",
    TAG_AP_CHANNEL_REPORT: "AP Channel Report",
    TAG_NEIGHBOR_REPORT: "Neighbor Report",
    TAG_RCPI: "RCPI",
    TAG_MOBILITY_DOMAIN: "Mobility Domain",
    TAG_FAST_BSS_TRANSITION: "Fast BSS Transition",
    TAG_TIMEOUT_INTERVAL: "Timeout Interval",
    TAG_RIC_DATA: "RIC Data",
    TAG_DSE_REG_LOCATION: "DSE Registered Location",
    TAG_SUPPORTED_OPERATING_CLASSES: "Supported Operating Classes",
    TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT: "Extended Channel Switch Announcement",
    TAG_HT_INFO: "HT Information (802.11n D1.10)",
    TAG_SECONDARY_CHANNEL_OFFSET: "Secondary Channel Offset (802.11n D1.10)",
    TAG_BSS_AVG_ACCESS_DELAY: "BSS Average Access Delay",
    TAG_ANTENNA: "Antenna",
    TAG_RSNI: "RSNI",
    TAG_MEASURE_PILOT_TRANS: "Measurement Pilot Transmission",
    TAG_BSS_AVB_ADM_CAPACITY: "BSS Available Admission Capacity",
    TAG_IE_68_CONFLICT: "BSS AC Access Delay/WAPI Parameter Set",
    TAG_TIME_ADV: "Time Advertisement",
    TAG_RM_ENABLED_CAPABILITY: "RM Enabled Capabilities",
    TAG_MULTIPLE_BSSID: "Multiple BSSID",
    TAG_20_40_BSS_CO_EX: "20/40 BSS Coexistence",
    TAG_20_40_BSS_INTOL_CH_REP: "20/40 BSS Intolerant Channel Report",
    TAG_OVERLAP_BSS_SCAN_PAR: "Overlapping BSS Scan Parameters",
    TAG_RIC_DESCRIPTOR: "RIC Descriptor",
    TAG_MMIE: "Management MIC",
    TAG_EVENT_REQUEST: "Event Request",
    TAG_EVENT_REPORT: "Event Report",
    TAG_DIAGNOSTIC_REQUEST: "Diagnostic Request",
    TAG_DIAGNOSTIC_REPORT: "Diagnostic Report",
    TAG_LOCATION_PARAMETERS: "Location Parameters",
    TAG_NO_BSSID_CAPABILITY: "Non Transmitted BSSID Capability",
    TAG_SSID_LIST: "SSID List",
    TAG_MULTIPLE_BSSID_INDEX: "Multiple BSSID Index",
    TAG_FMS_DESCRIPTOR: "FMS Descriptor",
    TAG_FMS_REQUEST: "FMS Request",
    TAG_FMS_RESPONSE: "FMS Response",
    TAG_QOS_TRAFFIC_CAPABILITY: "QoS Traffic Capability",
    TAG_BSS_MAX_IDLE_PERIOD: "BSS Max Idle Period",
    TAG_TFS_REQUEST: "TFS Request",
    TAG_TFS_RESPONSE: "TFS Response",
    TAG_WNM_SLEEP_MODE: "WNM-Sleep Mode",
    TAG_TIM_BROADCAST_REQUEST: "TIM Broadcast Request",
    TAG_TIM_BROADCAST_RESPONSE: "TIM Broadcast Response",
    TAG_COLLOCATED_INTER_REPORT: "Collocated Interference Report",
    TAG_CHANNEL_USAGE: "Channel Usage",
    TAG_TIME_ZONE: "Time Zone",
    TAG_DMS_REQUEST: "DMS Request",
    TAG_DMS_RESPONSE: "DMS Response",
    TAG_LINK_IDENTIFIER: "Link Identifier",
    TAG_WAKEUP_SCHEDULE: "Wakeup Schedule",
    TAG_CHANNEL_SWITCH_TIMING: "Channel Switch Timing",
    TAG_PTI_CONTROL: "PTI Control",
    TAG_PU_BUFFER_STATUS: "PU Buffer Status",
    TAG_INTERWORKING: "Interworking",
    TAG_ADVERTISEMENT_PROTOCOL: "Advertisement Protocol",
    TAG_EXPIDITED_BANDWIDTH_REQ: "Expedited Bandwidth Request",
    TAG_QOS_MAP_SET: "QoS Map Set",
    TAG_ROAMING_CONSORTIUM: "Roaming Consortium",
    TAG_EMERGENCY_ALERT_ID: "Emergency Alert Identifier",
    TAG_MESH_CONFIGURATION: "Mesh Configuration",
    TAG_MESH_ID: "Mesh ID",
    TAG_MESH_LINK_METRIC_REPORT: "Mesh Link Metric Report",
    TAG_CONGESTION_NOTIFICATION: "Congestion Notification",
    TAG_MESH_PEERING_MGMT: "Mesh Peering Management",
    TAG_MESH_CHANNEL_SWITCH: "Mesh Channel Switch Parameters",
    TAG_MESH_AWAKE_WINDOW: "Mesh Awake Window",
    TAG_BEACON_TIMING: "Beacon Timing",
    TAG_MCCAOP_SETUP_REQUEST: "MCCAOP Setup Request",
    TAG_MCCAOP_SETUP_REPLY: "MCCAOP SETUP Reply",
    TAG_MCCAOP_ADVERTISEMENT: "MCCAOP Advertisement",
    TAG_MCCAOP_TEARDOWN: "MCCAOP Teardown",
    TAG_GANN: "Gate Announcement",
    TAG_RANN: "Root Announcement",
    TAG_EXTENDED_CAPABILITIES: "Extended Capabilities",
    TAG_AGERE_PROPRIETARY: "Agere Proprietary",
    TAG_MESH_PREQ: "Path Request",
    TAG_MESH_PREP: "Path Reply",
    TAG_MESH_PERR: "Path Error",
    TAG_CISCO_CCX1_CKIP: "Cisco CCX1 CKIP + Device Name",
    TAG_CISCO_CCX2: "Cisco CCX2",
    TAG_PXU: "Proxy Update",
    TAG_PXUC: "Proxy Update Confirmation",
    TAG_AUTH_MESH_PEERING_EXCH: "Auhenticated Mesh Perring Exchange",
    TAG_MIC: "MIC (Message Integrity Code)",
    TAG_DESTINATION_URI: "Destination URI",
    TAG_U_APSD_COEX: "U-APSD Coexistence",
    TAG_WAKEUP_SCHEDULE_AD: "Wakeup Schedule 802.11ad",
    TAG_EXTENDED_SCHEDULE: "Extended Schedule",
    TAG_STA_AVAILABILITY: "STA Availability",
    TAG_DMG_TSPEC: "DMG TSPEC",
    TAG_NEXT_DMG_ATI: "Next DMG ATI",
    TAG_DMG_CAPABILITIES: "DMG Capabilities",
    TAG_CISCO_CCX3: "Cisco Unknown 95",
    TAG_CISCO_VENDOR_SPECIFIC: "Vendor Specific",
    TAG_DMG_OPERATION: "DMG Operating",
    TAG_DMG_BSS_PARAMETER_CHANGE: "DMG BSS Parameter Change",
    TAG_DMG_BEAM_REFINEMENT: "DMG Beam Refinement",
    TAG_CHANNEL_MEASURMENT_FB: "Channel Measurement Feedback",
    TAG_AWAKE_WINDOW: "Awake Window",
    TAG_MULTI_BAND: "Multi Band",
    TAG_ADDBA_EXT: "ADDBA Extension",
    TAG_NEXTPCP_LIST: "NEXTPCP List",
    TAG_PCP_HANDOVER: "PCP Handover",
    TAG_DMG_LINK_MARGIN: "DMG Link Margin",
    TAG_SWITCHING_STREAM: "Switching Stream",
    TAG_SESSION_TRANSMISSION: "Session Transmission",
    TAG_DYN_TONE_PAIR_REP: "Dynamic Tone Pairing Report",
    TAG_CLUSTER_REP: "Cluster Report",
    TAG_RELAY_CAPABILITIES: "Relay Capabilities",
    TAG_RELAY_TRANSFER_PARAM: "Relay Transfer Parameter",
    TAG_BEAMLINK_MAINTENANCE: "Beamlink Maintenance",
    TAG_MULTIPLE_MAC_SUBLAYERS: "Multiple MAC Sublayers",
    TAG_U_PID: "U-PID",
    TAG_DMG_LINK_ADAPTION_ACK: "DMG Link Adaption Acknowledgment",
    TAG_SYMBOL_PROPRIETARY: "Symbol Proprietary",
    TAG_MCCAOP_ADVERTISEMENT_OV: "MCCAOP Advertisement Overview",
    TAG_QUIET_PERIOD_REQ: "Quiet Period Request",
    TAG_QUIET_PERIOD_RES: "Quiet Period Response",
    TAG_ECAPC_POLICY: "ECAPC Policy",
    TAG_CLUSTER_TIME_OFFSET: "Cluster Time Offset",
    TAG_ANTENNA_SECTOR_ID: "Antenna Sector ID",
    TAG_VHT_CAPABILITY: "VHT Capabilities",
    TAG_VHT_OPERATION: "VHT Operation",
    TAG_EXT_BSS_LOAD: "Extended BSS Load",
    TAG_WIDE_BW_CHANNEL_SWITCH: "Wide Bandwidth Channel Switch",
    TAG_VHT_TX_PWR_ENVELOPE: "VHT Tx Power Envelope",
    TAG_CHANNEL_SWITCH_WRAPPER: "Channel Switch Wrapper",
    TAG_OPERATING_MODE_NOTIFICATION: "Operating Mode Notification",
    TAG_S1G_OPEN_LOOP_LINK_MARGIN_INDEX: "S1G Open-Loop Link Margin Index",
    TAG_RPS: "RPS",
    TAG_PAGE_SLICE: "Page Slice",
    TAG_AID_REQUEST: "AID Request",
    TAG_AID_RESPONSE: "AID Response",
    TAG_S1G_SECTOR_OPERATION: "Sector Operation",
    TAG_S1G_BEACON_COMPATIBILITY: "S1G Beacon Compatibility",
    TAG_SHORT_BEACON_INTERVAL: "Short Beacon Interval",
    TAG_CHANGE_SEQUENCE: "Change Sequence",
    TAG_TWT: "Target Wake Time",
    TAG_S1G_CAPABILITIES: "S1G Capabilities",
    TAG_SUBCHANNEL_SELECTIVE_TRANSMISSION: "Subchannel Selective Transmission",
    TAG_VENDOR_SPECIFIC_IE: "Vendor Specific",
    TAG_AUTHENTICATION_CONTROL: "Authentication Control",
    TAG_TSF_TIMER_ACCURACY: "TSF Timer Accuracy",
    TAG_S1G_RELAY: "S1G Relay",
    TAG_REACHABLE_ADDRESS: "Reachable Address",
    TAG_S1G_RELAY_DISCOVERY: "S1G Relay Discovery",
    TAG_AID_ANNOUNCEMENT: "AID Announcement",
    TAG_PV1_PROBE_RESPONSE_OPTION: "PV1 Probe Response Option",
    TAG_EL_OPERATION: "EL Operation",
    TAG_SECTORIZED_GROUP_ID_LIST: "Sectorized Group ID List",
    TAG_S1G_OPERATION: "S1G Operation",
    TAG_HEADER_COMPRESSION: "Header Compression",
    TAG_SST_OPERATION: "SST Operation",
    TAG_MAD: "MAD",
    TAG_S1G_RELAY_ACTIVATION: "S1G Relay Activation",
    TAG_CAG_NUMBER: "CAG Number",
    TAG_AP_CSN: "AP-CSN",
    TAG_FILS_INDICATION: "FILS Indication",
    TAG_DIFF_INITIAL_LINK_SETUP: "Differential Initial Link Setup",
    TAG_FRAGMENT: "Fragment",
    TAG_ELEMENT_ID_EXTENSION: "Element ID Extension",
}

MICROSOFT_OUI = "\x00\x50\xF2"
VENDOR_SPECIFIC_WPA_ID = "\x01"


def get_frame_type(frame_control):
    """
    Returns frame type.
    """
    return (frame_control[0] & 0b00001100) >> 2


def get_frame_subtype(frame_control):
    """
    Returns frame subtype.
    """
    return (frame_control[0] & 0b11110000) >> 4


def get_security(frame):
    """Returns the network security. The values can be OPEN, WEP, WPA or WPA2."""
    cap = frame.get_capabilities()

    def is_wpa_ie_present(vendor_specific_ies):
        for oui, data in vendor_specific_ies:
            if oui == MICROSOFT_OUI and data[0] == VENDOR_SPECIFIC_WPA_ID:
                return True
        return False

    if cap & dot11.Dot11ManagementCapabilities.CAPABILITY_PRIVACY == 0:
        return "OPEN"
    else:
        if frame._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.RSN):
            return "WPA2"
        elif is_wpa_ie_present(frame.get_vendor_specific()):
            return "WPA"
        else:
            return "WEP"


def get_string_mac_address_from_buffer(buff):
    """Returns string representation of a MAC address from a buffer."""
    return ":".join('%02x' % octet for octet in buff)


def get_string_mac_address_from_array(buff):
    """Returns string representation of a MAC address from a array."""
    return ":".join('%02x' % octet for octet in buff)


def get_buffer_from_string_mac_address(mac_address):
    """Returns buffer representation of a MAC address from a string."""
    result = str()
    for octet in mac_address.split(":"):
        result += chr(int(octet, 16))
    return result
