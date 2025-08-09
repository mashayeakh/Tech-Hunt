import { useQuery } from "@tanstack/react-query";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import { Shield, UserCog, XCircle, Search, Filter } from "lucide-react";
import Swal from "sweetalert2";
import { Helmet } from "react-helmet-async";
import { useState } from "react";

const ManageUsers = () => {
    const axiosSecure = useAxiosSecure();
    const [searchTerm, setSearchTerm] = useState("");
    const [roleFilter, setRoleFilter] = useState("all");

    const { data: users = [], refetch, isError, isLoading } = useQuery({
        queryKey: ['users'],
        queryFn: async () => {
            try {
                const res = await axiosSecure.get('/users');
                return res.data;
            } catch (error) {
                throw new Error('Failed to fetch users');
            }
        }
    });

    const handleRoleChange = async (user, newRole) => {
        if (!user?._id || !user?.name) {
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Invalid User Data",
                text: "Unable to process user information.",
                showConfirmButton: false,
                timer: 1500
            });
            return;
        }

        const currentRole = user.role;
        const currentUserEmail = localStorage.getItem('userEmail');
        if (user.email === currentUserEmail && user.role === 'admin') {
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Not Allowed",
                text: "You cannot remove your own admin role.",
                showConfirmButton: false,
                timer: 1500
            });
            return;
        }

        const confirmResult = await Swal.fire({
            title: 'Are you sure?',
            text: newRole === currentRole
                ? `Remove ${currentRole} role from ${user.name}?`
                : `Make ${user.name} a ${newRole}?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: 'var(--bg-accent)',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, proceed!'
        });

        if (!confirmResult.isConfirmed) return;

        const endpoint = newRole === currentRole
            ? `/users/remove-role/${user._id}`
            : `/users/${newRole}/${user._id}`;

        try {
            const res = await axiosSecure.patch(endpoint);
            if (res.data.modifiedCount > 0) {
                await refetch();
                Swal.fire({
                    position: "top-end",
                    icon: "success",
                    title: newRole === currentRole
                        ? `${user.name}'s ${currentRole} role has been removed`
                        : `${user.name} is now a ${newRole}`,
                    showConfirmButton: false,
                    timer: 1500
                });
            } else {
                throw new Error('Role update did not modify any user');
            }
        } catch (error) {
            console.error('Role change error:', error);
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Failed",
                text: error.response?.data?.message || "There was an error updating the user role.",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const filteredUsers = users.filter(user => {
        const matchesSearch = user.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                             user.email?.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesRole = roleFilter === "all" || user.role === roleFilter || (!user.role && roleFilter === "user");
        return matchesSearch && matchesRole;
    });

    if (isLoading) {
        return (
            <div className="flex justify-center items-center min-h-screen custom-bg-primary">
                <div className="w-12 h-12 border-2 border-t-transparent border-[var(--bg-accent)] rounded-full animate-spin"></div>
            </div>
        );
    }

    if (isError) {
        return (
            <div className="flex justify-center items-center min-h-screen custom-bg-primary">
                <div className="text-center">
                    <h2 className="chakra text-2xl font-bold text-red-500 mb-4">Error Loading Users</h2>
                    <button
                        className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                        onClick={() => refetch()}
                    >
                        Try Again
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Manage Users | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    Manage Users
                </h2>

                <div className="custom-bg-secondary rounded-xl shadow-lg p-6 mb-8">
                    <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-6">
                        <div className="relative w-full md:w-1/2">
                            <input
                                type="text"
                                placeholder="Search by name or email..."
                                className="w-full p-3 pl-10 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 custom-text-secondary" />
                        </div>
                        <div className="flex items-center gap-2">
                            <Filter className="h-4 w-4 custom-text-secondary" />
                            <select
                                className="p-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                value={roleFilter}
                                onChange={(e) => setRoleFilter(e.target.value)}
                            >
                                <option value="all">All Roles</option>
                                <option value="admin">Admin</option>
                                <option value="moderator">Moderator</option>
                                <option value="user">User</option>
                            </select>
                        </div>
                    </div>
                    <div className="text-sm custom-text-secondary">
                        Total Users: {filteredUsers.length}
                    </div>
                </div>

                {filteredUsers.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {filteredUsers.map((user) => (
                            <div
                                key={user._id}
                                className="custom-bg-secondary rounded-xl shadow-lg p-5 border border-[var(--bg-accent)]/10 hover:shadow-xl hover:bg-[var(--bg-accent)]/5 transition-all duration-300 backdrop-blur-sm"
                            >
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-full bg-[var(--bg-accent)]/10 flex items-center justify-center text-lg custom-text-accent font-medium">
                                        {user.name?.charAt(0).toUpperCase() || 'U'}
                                    </div>
                                    <div>
                                        <h3 className="chakra text-base font-bold custom-text-primary line-clamp-1">
                                            {user.name}
                                        </h3>
                                        <p className="text-xs custom-text-secondary line-clamp-1">{user.email}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 mb-4">
                                    <span
                                        className={`px-2 py-1 text-xs font-medium rounded-full ${
                                            user.membershipStatus === 'active'
                                                ? 'bg-green-100 text-green-700'
                                                : 'bg-gray-100 text-gray-700'
                                        }`}
                                    >
                                        {user.membershipStatus === 'active' ? 'Premium' : 'Free'}
                                    </span>
                                    <span
                                        className={`px-2 py-1 text-xs font-medium rounded-full ${
                                            user.role === 'admin'
                                                ? 'bg-blue-100 text-blue-700'
                                                : user.role === 'moderator'
                                                ? 'bg-purple-100 text-purple-700'
                                                : 'bg-[var(--bg-accent)]/10 custom-text-accent'
                                        }`}
                                    >
                                        {user.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'User'}
                                    </span>
                                </div>
                                <div className="flex gap-2 flex-wrap">
                                    <button
                                        onClick={() => handleRoleChange(user, 'moderator')}
                                        className={`btn btn-sm ${
                                            user.role === 'moderator'
                                                ? 'text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10'
                                                : 'custom-bg-accent text-white hover:opacity-90'
                                        } rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom`}
                                        data-tip={user.role === 'moderator' ? 'Remove Moderator' : 'Make Moderator'}
                                        disabled={user.role === 'admin' || user.email === localStorage.getItem('userEmail')}
                                    >
                                        <Shield size={12} />
                                        {user.role === 'moderator' ? 'Remove Mod' : 'Make Mod'}
                                    </button>
                                    <button
                                        onClick={() => handleRoleChange(user, 'admin')}
                                        className={`btn btn-sm ${
                                            user.role === 'admin'
                                                ? 'text-red-500 hover:bg-red-50 dark:hover:bg-red-900/10'
                                                : 'custom-bg-accent text-white hover:opacity-90'
                                        } rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom`}
                                        data-tip={user.role === 'admin' ? 'Remove Admin' : 'Make Admin'}
                                        disabled={user.email === localStorage.getItem('userEmail')}
                                    >
                                        <UserCog size={12} />
                                        {user.role === 'admin' ? 'Remove Admin' : 'Make Admin'}
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="text-center py-16 custom-text-secondary">
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            className="h-16 w-16 mx-auto custom-text-accent opacity-30 mb-4"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth="1.5"
                                d="M12 4.5v15m7.5-7.5h-15"
                            />
                        </svg>
                        <h3 className="chakra text-xl font-bold custom-text-primary">
                            No Users Found
                        </h3>
                        <p className="mt-2 text-sm">
                            Try adjusting your search or filter to find users.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ManageUsers;