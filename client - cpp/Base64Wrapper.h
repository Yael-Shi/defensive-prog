/*
This file was written by the "Defensive Systems Programming of the Open University" course team.
*/

#pragma once

#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
