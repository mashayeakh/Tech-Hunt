import { useContext, useEffect, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import { AuthContext } from "../../providers/AuthProvider";
import useUpvote from "../../hooks/useUpvote";

const Navbar = () => {
    const [upvote] = useUpvote();
    const { user, logOut } = useContext(AuthContext);
    const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "light");
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem("theme", theme);
    }, [theme]);

    const handleThemeChange = () => {
        setTheme((prevTheme) => (prevTheme === "light" ? "dark" : "light"));
    };

    const handleLogOut = () => {
        logOut()
            .then(() => {})
            .catch(error => console.log(error));
    };

    const getDashboardRoute = () => {
        if (user?.role === "admin") return "/dashboard/statistics";
        if (user?.role === "moderator") return "/dashboard/reviewQueue";
        return "/dashboard/profile";
    };

    const navLinks = [
        { to: "/", label: "Home" },
        { to: "/products", label: "Products" },
        { to: "/about", label: "About" },
        ...(user ? [
            { to: "/coupons", label: "Coupons" },
            { to: "/dashboard/profile", label: "My Profile" }
        ] : [])
    ];

    return (
        <div className="custom-bg-secondary backdrop-blur-sm border-b border-gray-200 dark:border-gray-800 sticky top-0 z-50 font-inter">
            <div className="container mx-auto max-w-6xl px-4">
                <div className="flex items-center justify-between h-16">
                    {/* Logo */}
                    <Link to="/" className="flex items-center gap-2">
                        <img className="w-8" src="/logo 2.png" alt="Tech Hunt Logo" />
                        <span className="font-semibold text-lg custom-text-primary">Tech Hunt</span>
                    </Link>

                    {/* Desktop Navigation */}
                    <div className="hidden md:flex items-center space-x-1">
                        {navLinks.map((link) => (
                            <NavLink
                                key={link.to}
                                to={link.to}
                                className={({ isActive }) =>
                                    `px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                                        isActive
                                            ? "custom-text-accent font-semibold"
                                            : "custom-text-primary"
                                    }`
                                }
                            >
                                {link.label}
                            </NavLink>
                        ))}
                    </div>

                    {/* Right section with actions */}
                    <div className="flex items-center gap-3">
                        {/* Upvotes button */}
                        {user && (
                            <Link 
                                to="/dashboard/upvotes" 
                                className="hidden md:flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-medium bg-gray-100 border custom-bg-secondary custom-text-accent hover:bg-gray-200 transition-colors"
                            >
                                Upvotes
                                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-white custom-text-accent text-xs shadow-sm custom-bg-secondary custom-text-accent">
                                    {upvote.length}
                                </span>
                            </Link>
                        )}

                        {/* Theme toggle */}
                        <button 
                            onClick={handleThemeChange}
                            className="p-2 rounded-full hover:bg-gray-100 transition-colors"
                            aria-label="Toggle theme"
                        >
                            {theme === "dark" ? (
                                <svg className="w-5 h-5 custom-text-accent" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" fillRule="evenodd" clipRule="evenodd" />
                                </svg>
                            ) : (
                                <svg className="w-5 h-5 custom-text-accent" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                                </svg>
                            )}
                        </button>

                        {/* User menu or login */}
                        {user ? (
                            <div className="relative">
                                <button 
                                    className="flex rounded-full focus:outline-none focus:ring-2 focus:ring-gray-200 dark:focus:ring-gray-700"
                                    onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                                >
                                    <img
                                        className="h-8 w-8 rounded-full object-cover border border-gray-200 dark:border-gray-700"
                                        src={user?.photoURL || "/default-user.png"}
                                        alt="User Avatar"
                                    />
                                </button>

                                {/* Dropdown menu */}
                                {mobileMenuOpen && (
                                    <div className="absolute right-0 mt-2 w-48 py-2 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none custom-bg-secondary z-10">
                                        <div className="px-4 py-2 text-sm custom-text-primary border-b border-gray-200 dark:border-gray-700">
                                            {user?.displayName || "User"}
                                        </div>
                                        <Link 
                                            to={getDashboardRoute()} 
                                            className="block px-4 py-2 text-sm custom-text-primary hover:custom-text-accent hover:bg-gray-100 dark:hover:bg-gray-800"
                                        >
                                            Dashboard
                                        </Link>
                                        <button 
                                            onClick={handleLogOut} 
                                            className="block w-full text-left px-4 py-2 text-sm custom-text-primary hover:custom-text-accent hover:bg-gray-100 dark:hover:bg-gray-800"
                                        >
                                            Logout
                                        </button>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <Link 
                                to="/login" 
                                className="px-4 py-1.5 rounded-md text-sm font-medium custom-text-accent border border-current hover:custom-bg-accent hover:border-transparent hover:custom-text-white transition-colors"
                            >
                                Login
                            </Link>
                        )}

                        {/* Mobile menu button */}
                        <button
                            className="md:hidden p-2 rounded-md custom-text-primary hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none"
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                        >
                            {mobileMenuOpen ? (
                                <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            ) : (
                                <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                                </svg>
                            )}
                        </button>
                    </div>
                </div>

                {/* Mobile menu, show/hide based on state */}
                {mobileMenuOpen && (
                    <div className="md:hidden border-t border-gray-200 dark:border-gray-800 py-3">
                        <div className="space-y-1 px-2">
                            {navLinks.map((link) => (
                                <NavLink
                                    key={link.to}
                                    to={link.to}
                                    className={({ isActive }) =>
                                        `block px-3 py-2 rounded-md text-base font-medium ${
                                            isActive
                                                ? "custom-text-accent"
                                                : "custom-text-primary hover:custom-text-accent hover:bg-gray-100 dark:hover:bg-gray-800"
                                        }`
                                    }
                                    onClick={() => setMobileMenuOpen(false)}
                                >
                                    {link.label}
                                </NavLink>
                            ))}
                            {user && (
                                <Link 
                                    to="/dashboard/upvotes" 
                                    className="flex items-center justify-between px-3 py-2 rounded-md text-base font-medium custom-text-primary hover:custom-text-accent hover:bg-gray-100 dark:hover:bg-gray-800"
                                    onClick={() => setMobileMenuOpen(false)}
                                >
                                    Upvotes
                                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-gray-100 custom-text-accent text-xs dark:bg-gray-800">
                                        {upvote.length}
                                    </span>
                                </Link>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Navbar;