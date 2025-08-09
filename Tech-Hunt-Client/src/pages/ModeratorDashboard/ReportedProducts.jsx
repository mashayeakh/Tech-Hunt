import { useQuery } from "@tanstack/react-query";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import { Link } from "react-router-dom";
import Swal from "sweetalert2";
import useAuth from "../../hooks/useAuth";
import { Helmet } from "react-helmet-async";
import { useState } from "react";
import { Eye, Trash2, AlertCircle } from "lucide-react";

const ReportedProducts = () => {
    const axiosSecure = useAxiosSecure();
    const { user } = useAuth();
    const [searchTerm, setSearchTerm] = useState("");

    const { data: reportedProducts = [], refetch, isLoading } = useQuery({
        queryKey: ['reported-products', user?.email],
        queryFn: async () => {
            try {
                const res = await axiosSecure.get('/products/reported');
                return res.data;
            } catch (error) {
                console.error("Error fetching reported products:", error);
                throw error;
            }
        }
    });

    const { data: reports = [] } = useQuery({
        queryKey: ['reports'],
        queryFn: async () => {
            try {
                const res = await axiosSecure.get('/reports');
                return res.data;
            } catch (error) {
                console.error("Error fetching reports:", error);
                throw error;
            }
        }
    });

    const handleDelete = async (id, productName) => {
        try {
            const result = await Swal.fire({
                title: 'Are you sure?',
                text: `Delete ${productName}?`,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: 'var(--bg-accent)',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, delete it!'
            });

            if (result.isConfirmed) {
                const res = await axiosSecure.delete(`/products/reported/${id}`);
                if (res.data.deletedCount > 0) {
                    Swal.fire({
                        position: "top-end",
                        icon: "success",
                        title: `${productName} deleted successfully!`,
                        showConfirmButton: false,
                        timer: 1500
                    });
                    refetch();
                }
            }
        } catch (error) {
            console.error('Error deleting product:', error);
            Swal.fire({
                position: "top-end",
                icon: "error",
                title: "Operation Failed",
                text: "Could not delete the product",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const handleViewReports = async (productId, productName) => {
        const productReports = reports.filter(report => report.productId === productId);

        if (productReports.length === 0) {
            Swal.fire({
                title: 'No Reports',
                text: `No detailed reports found for ${productName}.`,
                icon: 'info',
                confirmButtonColor: 'var(--bg-accent)'
            });
            return;
        }

        const reportsList = productReports.map(report => `
            <div class="mb-4 p-4 bg-[var(--bg-secondary)] rounded-lg border border-[var(--bg-accent)]/20">
                <p><strong>Reported By:</strong> ${report.reportedBy}</p>
                <p><strong>Reason:</strong> ${report.reason}</p>
                <p><strong>Date:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
            </div>
        `).join('');

        await Swal.fire({
            title: `Report Details for ${productName}`,
            html: `<div class="max-h-[60vh] overflow-y-auto">${reportsList}</div>`,
            width: '600px',
            confirmButtonText: 'Close',
            confirmButtonColor: 'var(--bg-accent)'
        });
    };

    const filteredProducts = reportedProducts.filter(product => {
        const matchesSearch = product.productName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                             product.ownerName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                             product.ownerEmail?.toLowerCase().includes(searchTerm.toLowerCase());
        return matchesSearch;
    });

    if (isLoading) {
        return (
            <div className="flex justify-center items-center min-h-screen custom-bg-primary">
                <div className="w-12 h-12 border-2 border-t-transparent border-[var(--bg-accent)] rounded-full animate-spin"></div>
            </div>
        );
    }

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Reported Products | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    Reported Products
                </h2>

                <div className="custom-bg-secondary rounded-xl shadow-lg p-6 mb-8">
                    <div className="relative w-full md:w-1/2 mx-auto">
                        <input
                            type="text"
                            placeholder="Search by product name, owner name, or email..."
                            className="w-full p-3 pl-10 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                        <Eye className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 custom-text-secondary" />
                    </div>
                    <div className="text-sm custom-text-secondary mt-4">
                        Total Reported Products: {filteredProducts.length}
                    </div>
                </div>

                {filteredProducts.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="w-full custom-bg-secondary rounded-xl shadow-lg">
                            <thead className="bg-[var(--bg-accent)]/10 custom-text-primary">
                                <tr>
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-tl-xl">#</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Product</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Owner</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Reports</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-tr-xl">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredProducts.map((product, index) => (
                                    <tr
                                        key={product._id}
                                        className={`border-b border-[var(--bg-accent)]/10 hover:bg-[var(--bg-accent)]/5 transition-all duration-200 ${
                                            index % 2 === 0 ? 'custom-bg-secondary' : 'bg-[var(--bg-accent)]/5'
                                        }`}
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
                                                        Reported: {reports.find(report => report.productId === product._id)?.timestamp
                                                            ? new Date(reports.find(report => report.productId === product._id).timestamp).toLocaleDateString()
                                                            : "N/A"}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="chakra font-semibold text-sm custom-text-primary">
                                                {product.ownerName}
                                            </div>
                                            <div className="text-xs custom-text-secondary">
                                                {product.ownerEmail}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 text-red-700">
                                                Reports: {reports.filter(report => report.productId === product._id).length}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 flex gap-2 flex-wrap">
                                            <button
                                                onClick={() => handleViewReports(product._id, product.productName)}
                                                className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom"
                                                data-tip="View Reports"
                                            >
                                                <AlertCircle size={12} />
                                                Reports
                                            </button>
                                            <Link to={`/product/${product._id}`}>
                                                <button
                                                    className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-xs tooltip tooltip-bottom"
                                                    data-tip="View Details"
                                                >
                                                    <Eye size={12} />
                                                    Details
                                                </button>
                                            </Link>
                                            <button
                                                onClick={() => handleDelete(product._id, product.productName)}
                                                className="btn btn-sm text-red-500 rounded-lg flex items-center gap-2 text-xs hover:bg-red-50 dark:hover:bg-red-900/10 tooltip tooltip-bottom"
                                                data-tip="Delete Product"
                                            >
                                                <Trash2 size={12} />
                                                Delete
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
                                d="M12 9v3m0 0v3m0-3h-3m3 0h3m-9 6h12a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                            />
                        </svg>
                        <h3 className="chakra text-xl font-bold custom-text-primary">
                            No Reported Products
                        </h3>
                        <p className="mt-2 text-sm">
                            When users report products, they will appear here.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ReportedProducts;