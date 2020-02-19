#include "binary_incept.h"
#include <iostream>


binary_incept::binary_incept()
{}

binary_incept::~binary_incept()
{}

std::pair<uint16_t, uint16_t> binary_incept::get_category_rule(std::string category_json, std::pair<head_part, body_part>& category_rule)
{
	Json::Reader js_reader;
	Json::Value js_value;
	uint16_t head_offset = 0;
	uint16_t body_offset = 0;
	head_part head_category_vec;
	body_part body_category_vec;
	if (!js_reader.parse(category_json, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value category_head = js_value["categoryRule"]["head_part"];
	if (category_head.size() != 0)
	{
		for (uint16_t i = 0; i < category_head.size(); i++)
		{
			std::cout << category_head.size() << std::endl;//debug
			uint16_t value_len = category_head[i]["value_len"].asInt();
			uint16_t endian_prop = category_head[i]["property"].asInt();
			uint16_t route = category_head[i]["route"].asInt();
			uint16_t verify_len = category_head[i]["valid_len"].asInt();
			uint16_t contain_head = category_head[i]["contain_head"].asInt();

			head_offset += value_len;
			boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t> category_head = boost::make_tuple(value_len, endian_prop, route, verify_len, contain_head);			
			head_category_vec.push_back(category_head);
		}
	}

	Json::Value category_body = js_value["categoryRule"]["body_part"];
	if (category_body.size() != 0)
	{
		for (uint16_t j = 0; j < category_body.size(); j++)
		{
			uint16_t value_len = category_head[j]["value_len"].asInt();
			uint16_t endian_prop = category_head[j]["property"].asInt();
			uint16_t route = category_head[j]["route"].asInt();
			uint16_t verify_len = category_head[j]["valid_len"].asInt();
			uint16_t contain_head = category_head[j]["contain_head"].asInt();

			body_offset += value_len;
			boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t> category_body = boost::make_tuple(value_len, endian_prop, route, verify_len, contain_head);
			body_category_vec.push_back(category_body);
		}
	}
	category_rule = std::make_pair(head_category_vec, body_category_vec);
	std::pair<uint16_t, uint16_t> offset_pair = std::make_pair(head_offset, body_offset);
	return offset_pair;
}

void binary_incept::build_rule_relate(std::string relate_json, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t>>>& rule_map)
{
	Json::Reader js_reader;
	Json::Value js_value;
	std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t>> rule_vec;
	if (!js_reader.parse(relate_json, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value data_obj = js_value["dataRules"];
	for (uint16_t i = 0; i < data_obj.size(); i++)
	{
		std::string route_rule = data_obj[i]["categoryValues"].asString();
		Json::Value data_rule = data_obj[i]["dataRule"];
		for (uint16_t j = 0; j < data_rule.size(); j++)
		{
			std::string key_name = data_rule[j]["key_name"].asString();
			uint16_t value_len = data_rule[j]["value_len"].asInt();
			uint16_t endian_prop = data_rule[j]["property"].asInt();
			uint16_t distinc_value = data_rule[j]["distinction"].asInt();
			boost::tuple<std::string, uint16_t, uint16_t, uint16_t> rule_tuple = boost::make_tuple(key_name, value_len, endian_prop, distinc_value);
			rule_vec.push_back(rule_tuple);
		}
		rule_map[route_rule] = rule_vec;
		rule_vec.clear();
	}
}

uint64_t binary_incept::part_parse(std::vector<boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t> > prop_vec, const unsigned char* pdata, std::string& category_string, uint16_t offset)
{
	char* pbuf = NULL;
	uint64_t verify_len = 0;
	for (std::vector<boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t> >::iterator iter = prop_vec.begin(); iter != prop_vec.end(); iter++)
	{	
		uint16_t offset_len = iter->get<0>();
		//0网络序，1主机序
		uint16_t property = iter->get<1>();
		uint16_t isroute = iter->get<2>();
		uint16_t valid_len = iter->get<3>();
		uint16_t is_contain_head = iter->get<4>();


		pbuf = (char*)malloc(offset_len * sizeof(char));
		if (pbuf != NULL)
		{
			memcpy(pbuf, pdata, offset_len);
		}
		//路由规则
		if (pbuf != NULL && 1 == isroute)
		{
			if (property == 0 || offset_len != 1)
			{
				EndianSwap(pbuf, 0, offset_len);
			}
			if (offset_len == 2) category_string += "," + to_string(*(uint16_t*)pbuf);
			else if (offset_len == 4) category_string += "," + to_string(*(uint32_t*)pbuf);
			else if (offset_len == 8) category_string += "," + to_string(*(uint64_t*)pbuf);
			else if (offset_len == 1)
			{
				int a = *(uint8_t*)pbuf;
				category_string += "," + to_string(a);
			}
			else
			{
				free(pbuf);
				pbuf = NULL;
				throw std::logic_error("整形长度不符合标准");
			}
			free(pbuf);
			pbuf = NULL;
		}
		//长度校验
		if (pbuf != NULL && 1 == valid_len)
		{
			if (property == 0)
			{
				EndianSwap(pbuf, 0, offset_len);
			}
			if (offset_len == 1) verify_len = *(uint8_t*)pbuf;
			else if (offset_len == 2) verify_len = *(uint16_t*)pbuf;
			else if (offset_len == 4) verify_len = *(uint32_t*)pbuf;
			else if (offset_len == 8) verify_len = *(uint64_t*)pbuf;

			if (1 != is_contain_head)
			{
				verify_len += offset;
			}
		}
		pdata += offset_len;
	}
	return verify_len;
}

std::vector<std::string> binary_incept::parse_category_rule(std::pair<head_part, body_part> category_pair, std::pair<uint16_t, uint16_t> offset_pair, const unsigned char* pdata, uint16_t data_len, std::vector<uint64_t>& part_len_vec)
{
	std::string categoty_rule;
	uint64_t parse_len = 0;
	
	std::string category_head_string;
	std::string category_body_string;
	std::vector<std::string> rule_vec;
	uint16_t head_offset = offset_pair.first;
	uint16_t body_offset = offset_pair.second;

	if (head_offset + body_offset >= data_len)
	{
		throw std::logic_error("数据长度不符合标准");
	}
	//总头解析
	if (category_pair.first.size() != 0)
	{
		uint64_t total_len = part_parse(category_pair.first, pdata, category_head_string, head_offset);
		if (total_len != 0 && total_len != data_len)
		{
			throw std::logic_error("数据长度不符合标准");
		}
		pdata += head_offset;
		parse_len += head_offset;
	}
	//分头解析
	if (category_pair.second.size() != 0)
	{
		uint64_t single_len = part_parse(category_pair.second, pdata, category_body_string, body_offset);
		rule_vec.push_back(category_body_string);
		part_len_vec.push_back(single_len);
		if (single_len != 0)
		{
			parse_len += single_len;
			while (parse_len < data_len)
			{
				std::string category_tmp;
				pdata += single_len;
				single_len = part_parse(category_pair.second, pdata, category_tmp, body_offset);
				rule_vec.push_back(category_tmp);
				parse_len += single_len;
				part_len_vec.push_back(single_len);
			}
		}
	}

	for (std::vector<std::string>::iterator iter = rule_vec.begin(); iter != rule_vec.end(); iter++)
	{
		*iter = category_head_string + (*iter);
		if (!(*iter).empty())
		{
			*iter = (*iter).substr(1);
		}
		else
		{
			std::cout << "no route rule!" << std::endl;
		}
	}
	
	return rule_vec;
}

std::string binary_incept::parse_data(std::vector<std::string> rule_vec, rule_unordered_map& rule_map, const unsigned char* pdata, uint16_t data_len, std::vector<uint64_t> part_len_vec, std::pair<uint16_t, uint16_t> head_offset)
{
	std::string key_value;
	char* pbuf = NULL;
	uint16_t parse_length = head_offset.first;
	pdata += head_offset.first;
	for (std::vector<std::string>::iterator iter = rule_vec.begin(); iter != rule_vec.end(); iter++)
	{
		std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t> > data_rule;
		rule_unordered_map::iterator it = rule_map.find(*iter);
		parse_length += head_offset.second;
		pdata += head_offset.second;
		
		if (it == rule_map.end())
		{
			throw std::logic_error("无响应数据解析规则");
		}
		
		data_rule = it->second;

		key_value += "##";

		for (std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t> >::iterator iterator = data_rule.begin(); iterator != data_rule.end(); iterator++)
		{
			std::string key = iterator->get<0>();
			uint16_t offset_len = iterator->get<1>();
			uint16_t property = iterator->get<2>();
			uint16_t distinction = iterator->get<3>();//1、IP地址 2、时间戳 3、整形 4、字符
			parse_length += offset_len;
			if (offset_len <= 0 || parse_length > data_len)
			{
				throw std::logic_error("数据长度不符合解析标准");
			}

			pbuf = (char*)malloc(offset_len * sizeof(char));
			if (pbuf != NULL)
			{
				memcpy(pbuf, pdata, offset_len);
			}
			pdata += offset_len;

			if (0 == property && 1 != offset_len)
			{
				EndianSwap(pbuf, 0, offset_len);
			}
			if (pbuf != NULL && (3 == distinction || 2 == distinction))
			{
				if (offset_len == 2) key_value += ";" + key + ":" + to_string(*(uint16_t*)pbuf);
				else if (offset_len == 4) key_value += ";" + key + ":" + to_string(*(uint32_t*)pbuf);
				else if (offset_len == 8) key_value += "," + key + ":" + to_string(*(uint64_t*)pbuf);
				else if (offset_len == 1)
				{
					int a = *(uint8_t*)pbuf;
					key_value += "," + key + ":" + to_string(a);
				}
			}
			if (pbuf != NULL && distinction == 1)
			{
				EndianSwap(pbuf, 0, offset_len);
				if (4 == offset_len)
				{
					char str[INET_ADDRSTRLEN];
					const char* ptr = inet_ntop(AF_INET, pbuf, str, sizeof(str));
					std::string value(ptr, strlen(str));
					key_value += ";" + key + ":" + value;
				}

				if (16 == offset_len)
				{
					char str[INET6_ADDRSTRLEN];
					const char* ptr = inet_ntop(AF_INET6, pbuf, str, sizeof(str));
					std::string value(ptr, strlen(str));
					key_value += ";" + key + ":" + value;
				}
			}
			if (pbuf != NULL && distinction == 4)
			{
				std::string value(pbuf, offset_len);
				key_value += ";" + key + ":" + value;
			}
			free(pbuf);
			pbuf = NULL;
		}
	}
	std::string parsed_data;
	if (!key_value.empty())
	{
		parsed_data = key_value.substr(3);
	}
	else
	{
		throw std::logic_error("数据解析为空");
	}
	return parsed_data;

}

void binary_incept::EndianSwap(char* pdata, uint16_t startIndex, uint16_t length)
{
	uint16_t i, cnt, end, start;
	cnt = length / 2;
	start = startIndex;
	end = startIndex + length - 1;
	char tmp;
	for (i = 0; i < cnt; i++)
	{
		tmp = pdata[start + i];
		pdata[start + i] = pdata[end - i];
		pdata[end - i] = tmp;
	}
}