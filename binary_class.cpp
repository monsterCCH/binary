#include "binary_incept.h"


binary_incept::binary_incept()
{}

binary_incept::~binary_incept()
{}

uint32_t binary_incept::get_category_rule(std::string& category_json, std::vector<std::pair<uint32_t, uint32_t>>& categoty_vec)
{
	Json::Reader js_reader;
	Json::Value js_value;
	uint32_t head_offset = 0;
	if (!js_reader.parse(category_json, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value category_obj = js_value["categoryRule"];
	for (int i = 0; i < category_obj.size(); i++)
	{
		uint32_t value_len = category_obj[i]["value_len"].asInt;
		uint32_t big_or_small = category_obj[i]["property"].asInt;
		head_offset += value_len;
		std::pair<uint32_t, uint32_t> category_pair = std::make_pair(value_len, big_or_small);
		categoty_vec.push_back(category_pair);
	}
	return head_offset;
}

void binary_incept::build_rule_relate(std::string& rule_relate, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint32_t, uint32_t>>>& rule_map)
{
	Json::Reader js_reader;
	Json::Value js_value;
	if (!js_reader.parse(rule_relate, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value date_obj = js_value["dataRules"];
	for (int i = 0; i < data_obj.size(); i++)
	{
		std::string regular = data_obj[i]["categoryValues"].asString();
		Json::Value key_obj = data_obj[i]["dataRule"];
		std::vector<boost::tuple<std::string, uint32_t, uint32_t>> rule;
		for (int j = 0; j < key_obj.size(); j++)
		{
			std::string key_name = key_obj[j]["key_name"].asString();
			uint32_t value_len = key_obj[j]["value_len"].asInt();
			uint32_t big_or_small = key_obj[j]["property"].asInt();
			boost::tuple<std::string, uint32_t, uint32_t> rule_tuple = boost::make_tuple(key_name, value_len, big_or_small);
			rule.push_back(rule_tuple);
		}
		rule_mapp[regular] = rule;
		rule.clear();
	}
}

std::string binary_incept::parse_category_rule(std::vector<std::pair<uint32_t, uint32_t> >& category_vec, const char* pdata, uint32_t data_len)
{
	std::string categoty_rule;
	uint32_t category_len = 0;
	char* pbuf = NULL;
	std::string category_string;

	for (std::vector<std::pair<uint32_t, uint32_t> >::iterator iter = category_vec.begin(); iter != category_vec.end(); iter++)
	{
		uint32_t offset_len = iter->first;
		//0大端，1小端
		uint32_t property = iter->second;
		category_len += offset_len;
		if (category_len >= data_len || offset_len <= 0)
		{
			throw std::logic_error("数据长度不符合标准");
		}
		pbuf = (char*)malloc(offset_len * sizeof(char));
		memcpy(pbuf, pdata, offset_len);

		if (offset_len == 2 || offset_len == 4 || offset_len == 8)
		{
			if (property == 0)
			{
				EndianSwap(pbuf, 0, offset_len);
			}

		}

	}
}
