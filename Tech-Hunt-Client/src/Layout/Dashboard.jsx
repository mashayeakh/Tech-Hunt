import { useEffect, useState } from "react";
import { FaHome } from "react-icons/fa";
import { CgProfile } from "react-icons/cg";
import { IoIosArrowDropupCircle } from "react-icons/io";
import { AiFillPlusCircle } from "react-icons/ai";
import { LuBox } from "react-icons/lu";
import { NavLink, Outlet } from "react-router-dom";
import useUpvote from "../hooks/useUpvote";
import { IoStatsChartSharp } from "react-icons/io5";
import { MdManageAccounts } from "react-icons/md";
import { RiCoupon2Fill } from "react-icons/ri";
import { MdQueue, MdReportProblem } from "react-icons/md";
import useAdmin from "../hooks/useAdmin";
import useModerator from "../hooks/useModerator";
import { TbLayoutSidebarRightCollapse, TbLayoutSidebarLeftCollapse } from "react-icons/tb";
import { GrTechnology } from "react-icons/gr";

const Dashboard = () => {
    const [upvote] = useUpvote();
    const [isAdmin] = useAdmin();
    const [isModerator] = useModerator();
    const [isSidebarOpen, setIsSidebarOpen] = useState(true); // Default to open
    const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "light");

    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem("theme", theme);
    }, [theme]);

    const handleThemeChange = () => {
        setTheme((prevTheme) => (prevTheme === "light" ? "dark" : "light"));
    };

    const handleNavClick = () => {
        // Only close sidebar on mobile
        if (window.innerWidth < 768) {
            setIsSidebarOpen(false);
        }
    };

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    const NavItem = ({ to, icon, children }) => (
        <li>
            <NavLink
                className={({ isActive }) =>
                    `flex gap-3 items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                        isActive
                            ? "bg-[var(--bg-accent)]/80 text-gray-100" // Lighter purple and high-contrast text
                            : "custom-text-primary hover:bg-[var(--bg-accent)]/10 hover:custom-text-accent"
                    }`
                }
                to={to}
                onClick={handleNavClick}
            >
                {icon}
                <span>{children}</span>
            </NavLink>
        </li>
    );

    return (
        <div className="min-h-screen custom-bg-primary font-inter">
            <div
                className={`fixed top-0 left-0 transition-all duration-300 custom-bg-secondary custom-text-primary w-64
                    ${isSidebarOpen ? "translate-x-0" : "-translate-x-full"} min-h-screen z-50 flex flex-col justify-between border-r border-[var(--bg-accent)]/20`}
            >
                <div>
                    <div className="flex flex-col items-center mb-10 pt-6">
                        <img className="w-12" src="/logo 2.png" alt="Tech Hunt Logo" />
                        <p className="chakra font-bold text-xl custom-text-primary mt-2">Tech Hunt</p>
                    </div>
                    <ul className="space-y-2 px-4">
                        {isAdmin ? (
                            <>
                                <NavItem to="/dashboard/statistics" icon={<IoStatsChartSharp size={20} />}>
                                    Statistics
                                </NavItem>
                                <NavItem to="/dashboard/manageUsers" icon={<MdManageAccounts size={20} />}>
                                    Manage Users
                                </NavItem>
                                <NavItem to="/dashboard/manageCoupons" icon={<RiCoupon2Fill size={20} />}>
                                    Manage Coupons
                                </NavItem>
                            </>
                        ) : isModerator ? (
                            <>
                                <NavItem to="/dashboard/reviewQueue" icon={<MdQueue size={20} />}>
                                    Product Review Queue
                                </NavItem>
                                <NavItem to="/dashboard/reportedProducts" icon={<MdReportProblem size={20} />}>
                                    Reported Products
                                </NavItem>
                            </>
                        ) : (
                            <>
                                <NavItem to="/dashboard/profile" icon={<CgProfile size={20} />}>
                                    My Profile
                                </NavItem>
                                <NavItem to="/dashboard/upvotes" icon={<IoIosArrowDropupCircle size={20} />}>
                                    My Upvotes ({upvote.length})
                                </NavItem>
                                <NavItem to="/dashboard/addProduct" icon={<AiFillPlusCircle size={20} />}>
                                    Add Product
                                </NavItem>
                                <NavItem to="/dashboard/myProducts" icon={<LuBox size={20} />}>
                                    My Products
                                </NavItem>
                            </>
                        )}
                        <div className="divider my-4 mx-2 border-[var(--bg-accent)]/20"></div>
                        <NavItem to="/" icon={<FaHome size={20} />}>
                            Home
                        </NavItem>
                        <NavItem to="/products" icon={<GrTechnology size={20} />}>
                            Products
                        </NavItem>
                    </ul>
                </div>

                <div className="px-6 pb-6 flex items-center gap-3">
                    <button
                        onClick={handleThemeChange}
                        className="p-2 rounded-full hover:bg-[var(--bg-accent)]/10 transition-colors"
                        aria-label="Toggle theme"
                    >
                        {theme === "dark" ? (
                            <svg
                                className="w-5 h-5 custom-text-accent"
                                fill="currentColor"
                                viewBox="0 0 20 20"
                                xmlns="http://www.w3.org/2000/svg"
                            >
                                <path
                                    fillRule="evenodd"
                                    d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"
                                    clipRule="evenodd"
                                />
                            </svg>
                        ) : (
                            <svg
                                className="w-5 h-5 custom-text-accent"
                                fill="currentColor"
                                viewBox="0 0 20 20"
                                xmlns="http://www.w3.org/2000/svg"
                            >
                                <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                            </svg>
                        )}
                    </button>
                    <span className="text-sm custom-text-primary">Change Theme</span>
                </div>
            </div>

            <button
                className="cursor-pointer custom-text-white p-3 fixed top-4 left-4 z-50 rounded-lg"
                onClick={toggleSidebar}
            >
                {isSidebarOpen ? (
                    <TbLayoutSidebarLeftCollapse size={24} />
                ) : (
                    <TbLayoutSidebarRightCollapse size={24} />
                )}
            </button>

            {isSidebarOpen && (
                <div
                    className="fixed inset-0 backdrop-blur-sm bg-[var(--bg-primary)]/30 z-40 md:hidden"
                    onClick={() => setIsSidebarOpen(false)}
                ></div>
            )}

            <div
                className={`min-h-screen transition-all duration-300 ${
                    isSidebarOpen ? "md:ml-64" : "md:ml-0"
                }`}
            >
                <div className="max-w-5xl mx-auto px-4 py-12">
                    <Outlet />
                </div>
            </div>
        </div>
    );
};

export default Dashboard;