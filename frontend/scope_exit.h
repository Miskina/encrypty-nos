#ifndef SCOPE_EXIT_H
#define SCOPE_EXIT_H

#include <tuple>

template<typename ... Ops>
struct scope_exit
{
public:
	scope_exit(Ops&&... ops) : ops_(std::forward<Ops>(ops)...) {}
	~scope_exit()
	{
		exit_impl(std::make_index_sequence<sizeof...(Ops)>{});
	}
	
private:
	std::tuple<Ops...> ops_;
	
	template<size_t ... I>
	void exit_impl(std::index_sequence<I...>)
	{
		(std::get<I>(ops_)(), ...);
	}
	
};

template<typename ... Ops>
scope_exit<Ops...> make_scope_exit(Ops&& ... ops)
{
	return scope_exit<Ops...>(std::forward<Ops>(ops)...);
}

#endif // SCOPE_EXIT_H
