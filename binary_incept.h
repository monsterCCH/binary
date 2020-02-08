#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <unordered_map>
#include <tuple>
#include <json/json.h>

class binary_incept
{
public:
	binary_incept();
	~binary_incept();

	uint32_t get_category_rule(std::string& category_json, std::vector<std::pair<uint32_t, uint32_t> >& category_vec);

	void build_rule_relate(std::string& rule_relate, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint32_t, uint32_t>>>& rule_map);

	std::string parse_category_rule(std::vector<std::pair<uint32_t, uint32_t> >& category_vec, const char* pdata, uint32_t data_len);

	std::string parse_data(std::string& category_combine, const char* pdata, uint32_t data_len, uint32_t head_offset);

	void EndianSwap(char* pData, uint32_t startIndex, uint32_t length);
};
