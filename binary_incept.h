#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <unordered_map>
#include <tuple>
#include <json/json.h>
#include <boost/unordered_map.hpp>
#include <boost/tuple/tuple.hpp>


template <typename T>
std::string to_string(T value)
{
	std::ostringstream os;
	os << value;
	return os.str();
}
class binary_incept
{
public:
	binary_incept();
	~binary_incept();

	uint16_t get_category_rule(std::string& category_json, std::vector<std::pair<uint16_t, uint16_t> >& category_vec);

	void build_rule_relate(std::string& rule_relate, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t>>>& rule_map);

	std::string parse_category_rule(std::vector<std::pair<uint16_t, uint16_t> >& category_vec, const unsigned char* pdata, uint16_t data_len);

	std::string parse_data(std::string& category_combine, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t>>>& rule_map, const unsigned char* pdata, uint16_t data_len, uint16_t head_offset);

	void EndianSwap(char* pdata, uint16_t startIndex, uint16_t length);
};
