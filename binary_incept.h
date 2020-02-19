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
#include <WS2tcpip.h>


template <typename T>
std::string to_string(T value)
{
	std::ostringstream os;
	os << value;
	return os.str();
}
typedef std::vector<boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>> head_part;
typedef std::vector<boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>> body_part;
typedef boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t>>> rule_unordered_map;

class binary_incept
{
public:
	binary_incept();
	~binary_incept();

	std::pair<uint16_t, uint16_t> get_category_rule(std::string category_json, std::pair<head_part, body_part>& category_rule);


	void build_rule_relate(std::string rule_relate, boost::unordered_map<std::string, std::vector<boost::tuple<std::string, uint16_t, uint16_t, uint16_t>>>& rule_map);

	uint64_t part_parse(std::vector<boost::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>> prop_vec, const unsigned char* pdata, std::string& category_string, uint16_t head_offset);


	std::vector<std::string> parse_category_rule(std::pair<head_part, body_part> category_pair, std::pair<uint16_t, uint16_t> offset_pair, const unsigned char* pdata, uint16_t data_len, std::vector<uint64_t>& part_len_vec);

	std::string parse_data(std::vector<std::string> rule_vec, rule_unordered_map& rule_map, const unsigned char* pdata, uint16_t data_len, std::vector<uint64_t> part_len_vec, std::pair<uint16_t, uint16_t> head_offset);



	void EndianSwap(char* pdata, uint16_t startIndex, uint16_t length);
};
