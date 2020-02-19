#include <iostream>
#include "binary_incept.h"

static std::string category_tmp = "{\"categoryRule\":{\"head_part\":[{\"value_len\":2,\"property\":0,\"route\":1,\"valid_len\":0,\"contain_head\":0},{\"value_len\":2,\"property\":0,\"route\":0,\"valid_len\":1,\"contain_head\":0}],\"body_part\":[{\"value_len\":2,\"property\":0,\"route\":1,\"valid_len\":0,\"contain_head\":0},{\"value_len\":2,\"property\":0,\"route\":0,\"valid_len\":1,\"contain_head\":0}]},\"dataRules\":[{\"categoryValues\":\"6,0\",\"dataRule\":[{\"key_name\":\"event_name\",\"value_len\":12,\"property\":0,\"distinction\":0},{\"key_name\":\"evenet_id\",\"value_len\":5,\"property\":1,\"distinction\":0},{\"key_name\":\"service_type\",\"value_len\":4,\"property\":0,\"distinction\":1},{\"key_name\":\"ip地址\",\"value_len\":6,\"property\":0,\"distinction\":2}]},{\"categoryValues\":\"258,4,67438087,2057\",\"dataRule\":[{\"key_name\":\"名称\",\"value_len\":12,\"property\":0},{\"key_name\":\"事件编号\",\"value_len\":5,\"property\":1},{\"key_name\":\"设备类型\",\"value_len\":4,\"property\":0},{\"key_name\":\"端口\",\"value_len\":6,\"property\":0}]}]}";
static std::string category_json = "{\"categoryRule\":{\"head_part\":[{\"value_len\":2,\"property\":0,\"route\":1,\"valid_len\":0,\"contain_head\":0},{\"value_len\":2,\"property\":0,\"route\":0,\"valid_len\":1,\"contain_head\":1}],\"body_part\":[{\"value_len\":2,\"property\":0,\"route\":1,\"valid_len\":0,\"contain_head\":0},{\"value_len\":2,\"property\":0,\"route\":0,\"valid_len\":1,\"contain_head\":1}]},\"dataRules\":[{\"categoryValues\":\"6,1\",\"dataRule\":[{\"key_name\":\"Protocol\",\"value_len\":1,\"property\":0,\"distinction\":3},{\"key_name\":\"TosIPv6\",\"value_len\":1,\"property\":0,\"distinction\":3},{\"key_name\":\"Operator\",\"value_len\":1,\"property\":0,\"distinction\":3},{\"key_name\":\"IpVersion\",\"value_len\":1,\"property\":0,\"distinction\":3},{\"key_name\":\"SourceIP\",\"value_len\":16,\"property\":0,\"distinction\":1},{\"key_name\":\"DestIP\",\"value_len\":16,\"property\":0,\"distinction\":1},{\"key_name\":\"SrcPort\",\"value_len\":2,\"property\":0,\"distinction\":3},{\"key_name\":\"DestPort\",\"value_len\":2,\"property\":0,\"distinction\":3},{\"key_name\":\"StartTime\",\"value_len\":4,\"property\":0,\"distinction\":2},{\"key_name\":\"EndTime\",\"value_len\":4,\"property\":0,\"distinction\":2},{\"key_name\":\"InTotalPkg\",\"value_len\":4,\"property\":0,\"distinction\":3},{\"key_name\":\"InTotalByte\",\"value_len\":4,\"property\":0,\"distinction\":3},{\"key_name\":\"OutTotalPkg\",\"value_len\":4,\"property\":0,\"distinction\":3},{\"key_name\":\"OutTotalByte\",\"value_len\":4,\"property\":0,\"distinction\":3},{\"key_name\":\"vsysId\",\"value_len\":2,\"property\":0,\"distinction\":3},{\"key_name\":\"vrfId\",\"value_len\":2,\"property\":0,\"distinction\":3},{\"key_name\":\"advanced\",\"value_len\":4,\"property\":0,\"distinction\":3}]},{\"categoryValues\":\"258,4,67438087,2057\",\"dataRule\":[{\"key_name\":\"名称\",\"value_len\":12,\"property\":0},{\"key_name\":\"事件编号\",\"value_len\":5,\"property\":1},{\"key_name\":\"设备类型\",\"value_len\":4,\"property\":0},{\"key_name\":\"端口\",\"value_len\":6,\"property\":0}]}]}";
static const unsigned char pdata[256] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 ,0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70 ,  0x35, 0x74, 0x38, 0x3e, 0x39 ,  0x57, 0x69, 0x6e, 0x64,   0xe5, 0xbe, 0x97, 0xe5, 0x88, 0xb0,   0xc0, 0xa8, 0x64, 0x1b };
const unsigned char packet_bytes[] = {
  0x00, 0x06, 0x00, 0x50, 0x00, 0x01, 0x00, 0x4c,
  0x06, 0x01, 0x06, 0x00, 

  0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x02, 0x17, 0x33, 0xff, 0xfe, 0xf2, 0xff, 0x04,
  0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

  0xe2, 0xe7, 0x00, 0x50,
  0x5d, 0xf8, 0xa2, 0xdb, 0x5d, 0xf8, 0xa2, 0xdb,
  0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0xee,
  0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0x76,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
}; 

//0xc0, 0xa8, 0x85, 0xfd,
//0x0a, 0xff, 0xc6, 0x36,

//0x20, 0x01, 0x0d, 0xa8,0xd0, 0x02, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xab, 0x19,
//0x26, 0x00, 0x14, 0x17,0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0xb8, 0x1c, 0xda, 0x68,

//0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//0x02, 0x17, 0x33, 0xff, 0xfe, 0xf2, 0xff, 0x04,
//0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
int main()
{
	binary_incept binary;
	std::pair<head_part, body_part> category_pair;
	std::vector<uint64_t> part_len_vec;
	boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t>>> rule_map;
	try
	{
		std::pair<uint16_t, uint16_t> head_offset = binary.get_category_rule(category_json, category_pair);
		std::cout << head_offset.first << "|" << head_offset.second << std::endl;
		binary.build_rule_relate(category_json, rule_map);
		
		std::vector<std::string> rule_vec = binary.parse_category_rule(category_pair, head_offset, packet_bytes, 80, part_len_vec);
		for (std::vector<std::string>::iterator iter = rule_vec.begin(); iter != rule_vec.end(); iter++)
		{
			std::cout << *iter << std::endl;
		}
		//std::cout << category_combine << std::endl;

		std::string parsed_data = binary.parse_data(rule_vec, rule_map, packet_bytes, 80, part_len_vec, head_offset);
		std::cout << parsed_data << std::endl;
	}
	catch (Json::LogicError& e)
	{
		std::cerr << e.what() << std::endl;
	}
	catch (std::exception & msg)
	{
		std::cerr << msg.what() << std::endl;
	}
	
	return 0;
}