#include "binary_incept.h"
#include <iostream>


binary_incept::binary_incept()
{}

binary_incept::~binary_incept()
{}

std::pair<uint16_t, uint16_t> binary_incept::get_category_rule(std::string& category_json, std::vector<std::pair<uint16_t, uint16_t>>& categoty_vec)
{
	Json::Reader js_reader;
	Json::Value js_value;
	uint16_t head_offset = 0;
	if (!js_reader.parse(category_json, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value category_obj = js_value["categoryRule"];
	for (uint16_t i = 0; i < category_obj.size(); i++)
	{
		std::cout << category_obj.size() << std::endl;
		uint16_t value_len = category_obj[i]["value_len"].asInt();
		uint16_t big_or_small = category_obj[i]["property"].asInt();
		head_offset += value_len;
		std::pair<uint16_t, uint16_t> category_pair = std::make_pair(value_len, big_or_small);
		categoty_vec.push_back(category_pair);
	}
	return head_offset;
}

void binary_incept::build_rule_relate(std::string& rule_relate, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t>>>& rule_map)
{
	Json::Reader js_reader;
	Json::Value js_value;
	if (!js_reader.parse(rule_relate, js_value))
	{
		throw std::logic_error("规则格式不是正确的JSON格式");
	}
	Json::Value data_obj = js_value["dataRules"];
	for (uint16_t i = 0; i < data_obj.size(); i++)
	{
		std::string regular = data_obj[i]["categoryValues"].asString();
		Json::Value key_obj = data_obj[i]["dataRule"];
		std::vector<boost::tuple<std::string, uint16_t, uint16_t>> rule;
		for (uint16_t j = 0; j < key_obj.size(); j++)
		{
			std::string key_name = key_obj[j]["key_name"].asString();
			uint16_t value_len = key_obj[j]["value_len"].asInt();
			uint16_t big_or_small = key_obj[j]["property"].asInt();
			boost::tuple<std::string, uint16_t, uint16_t> rule_tuple = boost::make_tuple(key_name, value_len, big_or_small);
			rule.push_back(rule_tuple);
		}
		rule_map[regular] = rule;
		rule.clear();
	}
}

std::string binary_incept::parse_category_rule(std::vector<std::pair<uint16_t, uint16_t> >& category_vec, const unsigned char* pdata, uint16_t data_len)
{
	std::string categoty_rule;
	uint16_t category_len = 0;
	char* pbuf = NULL;
	std::string category_string;

	for (std::vector<std::pair<uint16_t, uint16_t> >::iterator iter = category_vec.begin(); iter != category_vec.end(); iter++)
	{
		uint16_t offset_len = iter->first;
		//0大端，1小端
		uint16_t property = iter->second;
		category_len += offset_len;
		if (category_len >= data_len || offset_len <= 0)
		{
			throw std::logic_error("数据长度不符合标准");
		}
		pbuf = (char*)malloc(offset_len * sizeof(char));
		if (pbuf != NULL)
		{
			memcpy(pbuf, pdata, offset_len);
		}

		if (pbuf != NULL)
		{
			if (offset_len == 2 || offset_len == 4 || offset_len == 8 || offset_len == 1)
			{
				if (property == 0 && offset_len != 1)
				{
					EndianSwap(pbuf, 0, offset_len);
				}
				if (offset_len == 2)
				{
					category_string += "," + to_string(*(uint16_t*)pbuf);
					pdata += offset_len;
				}
				if (offset_len == 4)
				{
					category_string += "," + to_string(*(uint16_t*)pbuf);
					pdata += offset_len;
				}
				if (offset_len == 8)
				{
					category_string += "," + to_string(*(uint64_t*)pbuf);
					pdata += offset_len;
				}
				if (offset_len == 1)
				{
					int a = *(uint8_t*)pbuf;
					category_string += "," + to_string(a);
					pdata += offset_len;
				}
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
	}

	if (!category_string.empty())
	{
		std::string category_combine = category_string.substr(1);
		return category_combine;
	}
	else
	{
		throw std::logic_error("无相应路由规则");
	}
}

std::string binary_incept::parse_data(std::string& category_combine, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t>>>& rule_map, const unsigned char* pdata, uint16_t data_len, uint16_t head_offset)
{
	std::string category = category_combine;
	std::vector<boost::tuple<std::string, uint16_t, uint16_t> > data_rule;
	boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t> > >::iterator iter = rule_map.find(category_combine);
	uint16_t total_length = head_offset;
	pdata += head_offset;
	if (iter == rule_map.end())
	{
		throw std::logic_error("无响应数据解析规则");
	}
	data_rule = iter->second;
	std::string key_value;
	char* pbuf = NULL;

	for (std::vector<boost::tuple<std::string, uint16_t, uint16_t> >::iterator it = data_rule.begin(); it != data_rule.end(); it++)
	{
		std::string key = it->get<0>();
		uint16_t offset_len = it->get<1>();
		uint16_t property = it->get<2>();
		total_length += offset_len;
		if (offset_len <= 0 || total_length > data_len)
		{
			throw std::logic_error("数据长度不符合解析标准");
		}

		pbuf = (char *)malloc(offset_len * sizeof(char));
		if (pbuf != NULL)
		{
			memcpy(pbuf, pdata, offset_len);
		}
		pdata += offset_len;

		if (1 == property)
		{
			EndianSwap(pbuf, 0, offset_len);
		}
		if (pbuf != NULL)
		{
			std::string value(pbuf, offset_len);
			key_value += ";" + key + ":" + value;
		}
		free(pbuf);
		pbuf = NULL;
	}
	if (!key_value.empty())
	{
		std::string parsed_data = key_value.substr(1);
		return parsed_data;
	}
	else
	{
		return "";
		throw std::logic_error("数据解析错误");
	}
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