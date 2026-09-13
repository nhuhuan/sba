module;
#include <string_view>
#include <type_traits>

export module sba.util:typelist;

export namespace SBA::Util {

	template <typename T>
	constexpr std::string_view type_name() noexcept {
		std::string_view p = __PRETTY_FUNCTION__;
		size_t start = p.find("T = ") + 4;
		size_t end = p.find_first_of(";]", start);
		std::string_view s = p.substr(start, end - start);
		size_t colon = s.rfind("::");
		return colon == std::string_view::npos ? s : s.substr(colon + 2);
	}

	template <typename... Ts>
	struct TypeList {};

	template <typename H, typename List>
	struct Prepend;

	template <typename H, typename... Ts>
	struct Prepend<H, TypeList<Ts...>> {
		using type = TypeList<H, Ts...>;
	};

	template <typename T, typename List>
	struct Insert;

	template <typename T>
	struct Insert<T, TypeList<>> {
		using type = TypeList<T>;
	};

	template <typename T, typename Head, typename... Tail>
	struct Insert<T, TypeList<Head, Tail...>> {
		using type = std::conditional_t<
			(type_name<T>().size() > type_name<Head>().size()),
			TypeList<T, Head, Tail...>,
			typename Prepend<
				Head,
				typename Insert<T, TypeList<Tail...>>::type
			>::type
		>;
	};

	template <typename List>
	struct Sort;

	template <>
	struct Sort<TypeList<>> {
		using type = TypeList<>;
	};

	template <typename Head, typename... Tail>
	struct Sort<TypeList<Head, Tail...>> {
		using type = typename Insert<
			Head,
			typename Sort<TypeList<Tail...>>::type
		>::type;
	};

	template <typename... Lists>
	struct Concat;

	template <>
	struct Concat<> {
		using type = TypeList<>;
	};

	template <typename List>
	struct Concat<List> {
		using type = List;
	};

	template <typename... T1, typename... T2, typename... Rest>
	struct Concat<TypeList<T1...>, TypeList<T2...>, Rest...> {
		using type = typename Concat<
			TypeList<T1..., T2...>,
			Rest...
		>::type;
	};

}
