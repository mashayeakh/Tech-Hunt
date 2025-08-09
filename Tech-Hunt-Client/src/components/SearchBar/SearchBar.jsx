import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import useAxiosSecure from '../../hooks/useAxiosSecure';
import { Search } from 'lucide-react';

const SearchBar = ({ onSearchResults }) => {
    const [searchParams, setSearchParams] = useSearchParams();
    const [searchTerm, setSearchTerm] = useState(searchParams.get('q') || '');
    const axiosSecure = useAxiosSecure();
    
    const handleSearch = async (e) => {
        e.preventDefault();
        if (searchTerm.trim()) {
            onSearchResults(searchTerm);
        } else {
            // If search is empty, clear search results
            onSearchResults('');
        }
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            handleSearch(e);
        }
    };

    return (
        <div className="relative flex h-12">
            <input
                type="text"
                placeholder="Search by tags or product name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={handleKeyDown}
                className="input input-bordered h-12 min-h-12 w-full rounded-r-none focus:outline-none"
            />
            <button 
                type="button" 
                onClick={handleSearch}
                className="btn btn-outline h-12 min-h-12 px-4 text-white bg-purple-600 rounded-l-none border-l-0"
            >
                <Search />
            </button>
        </div>
    );
};

export default SearchBar;