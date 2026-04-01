#pragma once
#include <string>
#include <array>

namespace crypto_utils
{
	template<size_t N>
	class XorString
	{
	public:
		constexpr XorString(const char(&str)[N]) : encrypted_data_{}
		{
			for (size_t i = 0; i < N; ++i)
			{
				encrypted_data_[i] = str[i] ^ key_;
			}
		}

		std::string Decrypt() const
		{
			std::string decrypted = "";
			for (size_t i = 0; i < N - 1; ++i)
			{
				decrypted += static_cast<char>(encrypted_data_[i] ^ key_);
			}
			return decrypted;
		}

	private:
		std::array<char, N> encrypted_data_;
		static constexpr char key_ = 0x77; 
	};

	#define XOR(str) crypto_utils::XorString<sizeof(str)>(str).Decrypt()
}
