import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import ProductItem from "../Shared/ProductItem";
import SearchBar from "../../components/SearchBar/SearchBar";
import ReactPaginate from "react-paginate";
import { Helmet } from "react-helmet-async";

const ITEMS_PER_PAGE = 6;

const Products = () => {
    const [products, setProducts] = useState([]);
    const [displayProducts, setDisplayProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [pageCount, setPageCount] = useState(0);
    const [itemOffset, setItemOffset] = useState(0);
    const [sortBy, setSortBy] = useState("recent");
    const axiosSecure = useAxiosSecure();
    const [searchParams, setSearchParams] = useSearchParams();

    useEffect(() => {
        const fetchProducts = async () => {
            setLoading(true);
            try {
                const searchTerm = searchParams.get('q');
                const sort = searchParams.get('sort') || 'recent';
                setSortBy(sort);
                
                const response = await axiosSecure.get(searchTerm 
                    ? `/products/search?q=${searchTerm}`
                    : '/products'
                );
                
                const acceptedProducts = response.data.filter(p => p.status === 'accepted');
                setProducts(acceptedProducts);
                
                // Initial sort of products
                applySorting(acceptedProducts, sort);
            } catch (error) {
                console.error('Error fetching products:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchProducts();
    }, [searchParams, axiosSecure]);

    // Apply sorting to products
    const applySorting = (productsToSort, sortType) => {
        let sorted = [...productsToSort];
        
        if (sortType === "popular") {
            sorted.sort((a, b) => (b.upvote || 0) - (a.upvote || 0));
        } else {
            sorted.sort((a, b) => {
                const aDate = new Date(a.timestamp || a.createdAt || 0);
                const bDate = new Date(b.timestamp || b.createdAt || 0);
                return bDate - aDate;
            });
        }
        
        setDisplayProducts(sorted);
        setPageCount(Math.ceil(sorted.length / ITEMS_PER_PAGE));
        setItemOffset(0);
    };

    // Handle sort option change
    const handleSortChange = (option) => {
        setSortBy(option);
        const newParams = new URLSearchParams(searchParams);
        newParams.set('sort', option);
        setSearchParams(newParams);
        applySorting(products, option);
    };

    const handleSearchResults = (searchTerm) => {
        const newParams = new URLSearchParams(searchParams);
        if (searchTerm) {
            newParams.set('q', searchTerm);
        } else {
            newParams.delete('q');
        }
        if (sortBy) {
            newParams.set('sort', sortBy);
        }
        setSearchParams(newParams);
    };

    const handlePageClick = (event) => {
        const newOffset = (event.selected * ITEMS_PER_PAGE) % displayProducts.length;
        setItemOffset(newOffset);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    // Get current products for display
    const getCurrentProducts = () => {
        const endOffset = itemOffset + ITEMS_PER_PAGE;
        return displayProducts.slice(itemOffset, endOffset);
    };

    return (
        <div className="custom-bg-primary px-4 py-8 font-inter min-h-screen">
            <Helmet>
                <title>Products | Tech Hunt</title>
            </Helmet>
            
            <div className="container mx-auto ">
                <div className="flex flex-col md:flex-row items-center mb-6 gap-4">
                    <div className="w-full md:w-2/3">
                        <SearchBar onSearchResults={handleSearchResults} />
                    </div>
                    <div className="w-full flex justify-end">
                        <div className="dropdown dropdown-end">
                            <label tabIndex={0} className="btn custom-bg-secondary custom-text-primary hover:bg-[var(--bg-accent)]/10">
                                {sortBy === "recent" ? "Recently Added" : "Most Popular"}
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 ml-1 custom-text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                            </label>
                            <ul tabIndex={0} className="dropdown-content z-[1] menu p-2 shadow custom-bg-secondary rounded-lg w-52">
                                <li className={sortBy === "recent" ? "bg-[var(--bg-accent)]/10" : ""}>
                                    <a onClick={() => handleSortChange("recent")} className="custom-text-primary">Recently Added</a>
                                </li>
                                <li className={sortBy === "popular" ? "bg-[var(--bg-accent)]/10" : ""}>
                                    <a onClick={() => handleSortChange("popular")} className="custom-text-primary">Most Popular</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                {loading ? (
                    <div className="flex justify-center">
                        <div className="w-12 h-12 border-2 border-t-transparent border-[var(--bg-accent)] rounded-full animate-spin"></div>
                    </div>
                ) : (
                    <div>
                        {displayProducts.length > 0 ? (
                            <>
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                                    {getCurrentProducts().map(product => (
                                        <ProductItem 
                                            key={product._id} 
                                            product={product}
                                        />
                                    ))}
                                </div>
                                
                                {pageCount > 1 && (
                                    <ReactPaginate
                                        breakLabel="..."
                                        nextLabel={
                                            <span className="flex items-center px-3 py-2 cursor-pointer custom-text-primary hover:custom-text-accent">
                                                Next <span className="ml-1">→</span>
                                            </span>
                                        }
                                        previousLabel={
                                            <span className="flex items-center px-3 py-2 cursor-pointer custom-text-primary hover:custom-text-accent">
                                                <span className="mr-1">←</span> Previous
                                            </span>
                                        }
                                        onPageChange={handlePageClick}
                                        pageRangeDisplayed={3}
                                        marginPagesDisplayed={2}
                                        pageCount={pageCount}
                                        renderOnZeroPageCount={null}
                                        containerClassName="flex items-center justify-center space-x-1 mt-8 mb-4"
                                        pageClassName="block border border-[var(--bg-accent)]/20 rounded hover:bg-[var(--bg-accent)]/10 transition-colors"
                                        pageLinkClassName="block px-3 py-2 text-sm custom-text-primary hover:custom-text-accent"
                                        previousClassName="block border border-[var(--bg-accent)]/20 rounded hover:bg-[var(--bg-accent)]/10 transition-colors"
                                        nextClassName="block border border-[var(--bg-accent)]/20 rounded hover:bg-[var(--bg-accent)]/10 transition-colors"
                                        breakClassName="block px-3 py-2 custom-text-secondary"
                                        activeClassName="custom-bg-accent border-[var(--bg-accent)]"
                                        activeLinkClassName="custom-text-white hover:custom-text-white"
                                        disabledClassName="opacity-50"
                                    />
                                )}
                                
                                <div className="text-center text-sm custom-text-secondary mt-4">
                                    Showing {itemOffset + 1} to {Math.min(itemOffset + ITEMS_PER_PAGE, displayProducts.length)} of {displayProducts.length} products
                                </div>
                            </>
                        ) : (
                            <div className="text-center py-8 custom-text-secondary">
                                <h3 className="chakra text-xl font-bold custom-text-primary">No products found</h3>
                                <p className="mt-2">Try adjusting your search criteria</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default Products;