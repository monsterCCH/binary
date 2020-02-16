#include <iostream>
#include "binary_incept.h"

static std::string category_json = "{\"categoryRule\":[{\"value_len\":2,\"property\":0},{\"value_len\":1,\"property\":0},{\"value_len\":4,\"property\":0},{\"value_len\":2,\"property\":0}],\"dataRules\":[{\"categoryValues\":\"258,3,67438087,2057\",\"dataRule\":[{\"key_name\":\"名称\",\"value_len\":12,\"property\":0},{\"key_name\":\"事件编号\",\"value_len\":5,\"property\":1},{\"key_name\":\"设备类型\",\"value_len\":4,\"property\":0},{\"key_name\":\"ip地址\",\"value_len\":6,\"property\":0}]}]}";
static const unsigned char pdata[256] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 ,0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70 ,  0x35, 0x74, 0x38, 0x3e, 0x39 ,  0x57, 0x69, 0x6e, 0x64,   0xe5, 0xbe, 0x97, 0xe5, 0x88, 0xb0,   0xc0, 0xa8, 0x64, 0x1b };
int main()
{
	binary_incept binary;
	std::vector<std::pair<uint16_t, uint16_t>> category_vec;
	boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t>>> rule_map;
	try
	{
		uint16_t head_offset = binary.get_category_rule(category_json, category_vec);
		std::cout << head_offset << std::endl;
		binary.build_rule_relate(category_json, rule_map);
		
		std::string category_combine = binary.parse_category_rule(category_vec, pdata, 10);
		std::cout << category_combine << std::endl;

		std::string parsed_data = binary.parse_data(category_combine, rule_map, pdata, 256, head_offset);
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