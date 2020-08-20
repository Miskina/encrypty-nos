#ifndef OPENSSL_TYPES_UTIL_HPP
#define OPENSSL_TYPES_UTIL_HPP

#include <stdexcept>
#include <limits>
#include <string>
#include <memory>
#include <vector>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rsa.h>

using byte = unsigned char;

namespace crypt
{
	
	template<typename T>
	struct zallocator
	{
		using value_type = T;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using reference = value_type&;
		using const_reference = const value_type&;
		using size_type = std::size_t;
		using difference_type = std::ptrdiff_t;
		
		pointer address(reference v)
		{
			return &v;
		}
		
		const_pointer address(const_reference v)
		{
			return &v;
		}
		
		pointer allocate(size_type n, const void* hint = 0) 
		{
			if(n > max_size()) throw std::bad_alloc();
			return static_cast<pointer>(::operator new(n * sizeof(T)));
		}
		
		void deallocate(pointer p, size_type n) 
		{
			OPENSSL_cleanse(p, n * sizeof(T));
			::operator delete(p);
		}
		
		constexpr size_type max_size() const 
		{
			return std::numeric_limits<size_type>::max() / sizeof(T);
		}
		
		template<typename U>
		struct rebind
		{
			using other = zallocator<U>;
		};
		
		
		void construct(pointer ptr, const_reference val) 
		{
			new (static_cast<T*>(ptr)) T(val);
		}
		
		void destroy(pointer ptr)
		{
			static_cast<T*>(ptr)->~T();
		}
		
		template<typename U, typename ... Args>
		void construct(U* ptr, Args&&... args) 
		{
			::new(static_cast<void*>(ptr)) U(std::forward<Args>(args)...);
		}
		
		template<typename U>
		void destroy(U* ptr)
		{
			ptr->~U();
		}
	};

	template<typename T1, typename T2>
	bool operator==(const zallocator<T1>&, const zallocator<T2>&)
	{
		return true;
	}

	template<typename T1, typename T2>
	bool operator!=(const zallocator<T1>&, const zallocator<T2>&)
	{
		return false;
	}
	
	void destroy_impl(EVP_MD_CTX * ctx);
	
	void destroy_impl(EVP_CIPHER_CTX * ctx);
	
	void destroy_impl(EVP_PKEY_CTX * ctx);
	
	void destroy_impl(EVP_PKEY * key);
	
	void destroy_impl(RSA * rsa);
	
	template<typename ... Args>
	struct scope_handler
	{
		constexpr scope_handler(Args*... args) : ptrs(std::make_tuple(args...)) {}
		
		~scope_handler()
		{
			destroy(std::make_index_sequence<sizeof...(Args)>{});
		}
		
	private:
		std::tuple<Args*...> ptrs;
		
		template<size_t ... N>
		void destroy(std::index_sequence<N...>)
		{
			(destroy_impl(std::get<N>(ptrs)), ...);
		}
	};
	
	template<typename ... Args>
	scope_handler<Args...> make_scope_handler(Args*... args)
	{
		return scope_handler(args...);
	}


}

using safe_string = std::basic_string<char, std::char_traits<char>, crypt::zallocator<char>>;
using safe_stringstream = std::basic_stringstream<char, std::char_traits<char>, crypt::zallocator<char>>;

template<typename T>
using safe_vector = std::vector<T, crypt::zallocator<T>>;


#endif // OPENSSL_TYPES_UTIL_HPP
