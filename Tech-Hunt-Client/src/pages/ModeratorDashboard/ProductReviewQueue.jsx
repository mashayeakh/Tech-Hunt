import { useQuery } from "@tanstack/react-query";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import { Link } from "react-router-dom";
import Swal from "sweetalert2";
import { Helmet } from "react-helmet-async";
import { useState } from "react";
import { Eye, CheckCircle, XCircle, Star, Filter } from "lucide-react";

const ProductReviewQueue = () => {
    const axiosSecure = useAxiosSecure();
    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");

    const { data: products = [], refetch } = useQuery({
        queryKey: ['review-queue'],
        queryFn: async () => {
            const res = await axiosSecure.get('/products/review-queue');
            return res.data.sort((a, b) => {
                const statusA = a.status || 'pending';
                const statusB = b.status || 'pending';
                if (statusA === 'pending' && statusB !== 'pending') return -1;
                if (statusA !== 'pending' && statusB === 'pending') return 1;
                if (a.timestamp && b.timestamp) {
                    return new Date(b.timestamp) - new Date(a.timestamp);
                }
                return 0;
            });
        }
    });

    const handleAccept = async (id, productName) => {
        try {
            await axiosSecure.patch(`/products/status/${id}`, {
                status: 'accepted'
            });
            Swal.fire({
                position: "top-end",
                icon: "success",
                title: `${productName} Accepted`,
                showConfirmButton: false,
                timer: 1500
            });
            refetch();
        } catch (error) {
            console.error('Error accepting product:', error);
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Failed",
                text: "Could not accept the product",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const handleReject = async (id, productName) => {
        try {
            await axiosSecure.patch(`/products/status/${id}`, {
                status: 'rejected',
                featured: false
            });
            Swal.fire({
                position: "top-end",
                icon: "success",
                title: `${productName} Rejected`,
                showConfirmButton: false,
                timer: 1500
            });
            refetch();
        } catch (error) {
            console.error('Error rejecting product:', error);
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Failed",
                text: "Could not reject the product",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const handleToggleFeatured = async (id, currentFeatured, productName) => {
        try {
            await axiosSecure.patch(`/products/status/${id}`, {
                featured: !currentFeatured
            });
            Swal.fire({
                position: "top-end",
                icon: "success",
                title: currentFeatured ? `${productName} Unfeatured` : `${productName} Featured`,
                showConfirmButton: false,
                timer: 1500
            });
            refetch();
        } catch (error) {
            console.error('Error updating featured status:', error);
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Failed",
                text: "Could not update featured status",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const filteredProducts = products.filter(product => {
        const matchesSearch = product.productName?.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesStatus = statusFilter === "all" || product.status === statusFilter || (!product.status && statusFilter === "pending");
        return matchesSearch && matchesStatus;
    });

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Product Review Queue | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    Product Review Queue
                </h2>

                <div className="custom-bg-secondary rounded-xl shadow-lg p-6 mb-8">
                    <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-6">
                        <div className="relative w-full md:w-1/2">
                            <input
                                type="text"
                                placeholder="Search by product name..."
                                className="w-full p-3 pl-10 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                            <Eye className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 custom-text-secondary" />
                        </div>
                        <div className="flex items-center gap-2">
                            <Filter className="h-4 w-4 custom-text-secondary" />
                            <select
                                className="p-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                value={statusFilter}
                                onChange={(e) => setStatusFilter(e.target.value)}
                            >
                                <option value="all">All Statuses</option>
                                <option value="pending">Pending</option>
                                <option value="accepted">Accepted</option>
                                <option value="rejected">Rejected</option>
                            </select>
                        </div>
                    </div>
                    <div className="text-sm custom-text-secondary">
                        Total Products: {filteredProducts.length}
                    </div>
                </div>

                {filteredProducts.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full custom-bg-secondary rounded-xl shadow-lg">
                            <thead className="bg-[var(--bg-accent)]/10 custom-text-primary">
                                <tr>
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-tl-xl">#</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Product</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-tr-xl">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredProducts.map((product, index) => (
                                    <tr
                                        key={product._id}
                                        className={`border-b border-[var(--bg-accent)]/10 hover:bg-[var(--bg-accent)]/5 transition-all duration-200 ${
                                            index % 2 === 0 ? 'custom-bg-secondary' : 'bg-[var(--bg-accent)]/5'
                                        } ${product.status === 'pending' ? 'bg-yellow-100/10' : ''}`}
                                    >
                                        <td className="px-4 py-3 text-sm custom-text-secondary">{index + 1}</td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-3">
                                                <img
                                                    src={product.productImage}
                                                    alt={product.productName}
                                                    className="w-10 h-10 object-contain rounded-lg"
                                                    onError={(e) => {
                                                        e.target.src = 'https://placehold.co/100x100?text=No+Image';
                                                    }}
                                                />
                                                <div>
                                                    <div className="chakra font-bold text-sm custom-text-primary line-clamp-1">
                                                        {product.productName}
                                                    </div>
                                                    <div className="text-xs custom-text-secondary">
                                                        by {product.ownerName}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-2">
                                                <span
                                                    className={`px-2 py-1 text-xs font-medium rounded-full ${
                                                        product.status === 'accepted'
                                                            ? 'bg-green-100 text-green-700'
                                                            : product.status === 'rejected'
                                                            ? 'bg-red-100 text-red-700'
                                                            : 'bg-yellow-100 text-yellow-700'
                                                    }`}
                                                >
                                                    {product.status || 'Pending'}
                                                </span>
                                                {product.featured && (
                                                    <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700">
                                                        Featured
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 flex gap-2 flex-wrap">
                                            <Link to={`/product/${product._id}`}>
                                                <button
                                                    className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom"
                                                    data-tip="View Details"
                                                >
                                                    <Eye size={12} />
                                                    Details
                                                </button>
                                            </Link>
                                            {product.status === 'accepted' && (
                                                <button
                                                    onClick={() => handleToggleFeatured(product._id, product.featured, product.productName)}
                                                    className={`btn btn-sm ${
                                                        product.featured
                                                            ? 'text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/10'
                                                            : 'custom-bg-accent text-white hover:opacity-90'
                                                    } rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom`}
                                                    data-tip={product.featured ? 'Unfeature' : 'Make Featured'}
                                                >
                                                    <Star size={12} />
                                                    {product.featured ? 'Unfeature' : 'Feature'}
                                                </button>
                                            )}
                                            <button
                                                onClick={() => handleAccept(product._id, product.productName)}
                                                className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom"
                                                data-tip="Accept Product"
                                                disabled={product.status === 'accepted'}
                                            >
                                                <CheckCircle size={12} />
                                                Accept
                                            </button>
                                            <button
                                                onClick={() => handleReject(product._id, product.productName)}
                                                className="btn btn-sm text-red-500 rounded-lg flex items-center gap-2 text-xs hover:bg-red-50 dark:hover:bg-red-900/10 tooltip tooltip-bottom"
                                                data-tip="Reject Product"
                                                disabled={product.status === 'rejected'}
                                            >
                                                <XCircle size={12} />
                                                Reject
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
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
                                d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
                            />
                        </svg>
                        <h3 className="chakra text-xl font-bold custom-text-primary">
                            No Products in Review Queue
                        </h3>
                        <p className="mt-2 text-sm">
                            There are currently no products awaiting review.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ProductReviewQueue;