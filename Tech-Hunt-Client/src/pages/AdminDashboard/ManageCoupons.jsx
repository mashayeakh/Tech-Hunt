import { useState, useEffect } from 'react';
import { Calendar, Tag, Trash2, Plus, Edit2 } from 'lucide-react';
import useAxiosSecure from '../../hooks/useAxiosSecure';
import { Helmet } from 'react-helmet-async';
import Swal from 'sweetalert2';

const ManageCoupons = () => {
    const [coupons, setCoupons] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isAdding, setIsAdding] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const axiosSecure = useAxiosSecure();
    const [formData, setFormData] = useState({
        code: '',
        expiryDate: '',
        description: '',
        discountAmount: ''
    });

    useEffect(() => {
        fetchCoupons();
    }, []);

    const fetchCoupons = async () => {
        try {
            setIsLoading(true);
            setError(null);
            const response = await axiosSecure.get('/coupons');
            setCoupons(Array.isArray(response.data) ? response.data : []);
        } catch (error) {
            console.error('Error fetching coupons:', error);
            setError('Failed to load coupons. Please try again later.');
            setCoupons([]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!formData.code || !formData.expiryDate || !formData.description || !formData.discountAmount) {
            setError('All fields are required.');
            return;
        }
        try {
            setError(null);
            if (isEditing) {
                await axiosSecure.patch(`/coupons/${formData._id}`, formData);
                Swal.fire({
                    position: "top-end",
                    icon: "success",
                    title: "Coupon updated successfully!",
                    showConfirmButton: false,
                    timer: 1500
                });
            } else {
                await axiosSecure.post('/coupons', formData);
                Swal.fire({
                    position: "top-end",
                    icon: "success",
                    title: "Coupon added successfully!",
                    showConfirmButton: false,
                    timer: 1500
                });
            }
            await fetchCoupons();
            setIsAdding(false);
            setIsEditing(false);
            setFormData({
                code: '',
                expiryDate: '',
                description: '',
                discountAmount: ''
            });
        } catch (error) {
            setError(`Failed to ${isEditing ? 'update' : 'add'} coupon. Please try again.`);
        }
    };

    const handleEdit = (coupon) => {
        setFormData({
            _id: coupon._id,
            code: coupon.code,
            expiryDate: new Date(coupon.expiryDate).toISOString().split('T')[0],
            description: coupon.description,
            discountAmount: coupon.discountAmount
        });
        setIsEditing(true);
        setIsAdding(true);
    };

    const handleDelete = async (id, code) => {
        const confirmResult = await Swal.fire({
            title: 'Are you sure?',
            text: `Delete coupon ${code}?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: 'var(--bg-accent)',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!'
        });

        if (confirmResult.isConfirmed) {
            try {
                setError(null);
                await axiosSecure.delete(`/coupons/${id}`);
                await fetchCoupons();
                Swal.fire({
                    position: "top-end",
                    icon: "success",
                    title: `${code} deleted successfully!`,
                    showConfirmButton: false,
                    timer: 1500
                });
            } catch (error) {
                setError('Failed to delete coupon. Please try again.');
            }
        }
    };

    const isExpired = (expiryDate) => {
        return new Date(expiryDate) < new Date();
    };

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
                <title>Manage Coupons | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-12">
                    <h2 className="chakra text-3xl font-bold custom-text-primary">
                        Manage Coupons
                    </h2>
                    <button
                        onClick={() => {
                            setIsAdding(true);
                            setIsEditing(false);
                            setFormData({
                                code: '',
                                expiryDate: '',
                                description: '',
                                discountAmount: ''
                            });
                        }}
                        className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-sm hover:opacity-90"
                    >
                        <Plus size={16} />
                        Add New Coupon
                    </button>
                </div>

                {isAdding && (
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-8 mb-8">
                        <h3 className="chakra text-xl font-bold custom-text-primary mb-6">
                            {isEditing ? 'Edit Coupon' : 'Add New Coupon'}
                        </h3>
                        <form onSubmit={handleSubmit} className="space-y-6">
                            {error && (
                                <div className="text-red-500 text-sm mb-4">{error}</div>
                            )}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Coupon Code
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="Enter coupon code"
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        value={formData.code}
                                        onChange={(e) => setFormData({ ...formData, code: e.target.value.toUpperCase() })}
                                    />
                                </div>
                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Expiry Date
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <input
                                        type="date"
                                        required
                                        min={new Date().toISOString().split('T')[0]}
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        value={formData.expiryDate}
                                        onChange={(e) => setFormData({ ...formData, expiryDate: e.target.value })}
                                    />
                                </div>
                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Discount Amount (%)
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <input
                                        type="number"
                                        required
                                        placeholder="Enter discount percentage"
                                        min="0"
                                        max="100"
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        value={formData.discountAmount}
                                        onChange={(e) => setFormData({ ...formData, discountAmount: Math.min(100, Math.max(0, e.target.value)) })}
                                    />
                                </div>
                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Description
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="Enter coupon description"
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        value={formData.description}
                                        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                                    />
                                </div>
                            </div>
                            <div className="flex justify-end gap-3">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setIsAdding(false);
                                        setIsEditing(false);
                                        setFormData({
                                            code: '',
                                            expiryDate: '',
                                            description: '',
                                            discountAmount: ''
                                        });
                                    }}
                                    className="btn btn-sm custom-bg-secondary custom-text-primary rounded-lg text-sm hover:bg-[var(--bg-accent)]/10"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                                >
                                    {isEditing ? 'Update Coupon' : 'Create Coupon'}
                                </button>
                            </div>
                        </form>
                    </div>
                )}

                {coupons.length === 0 ? (
                    <div className="text-center py-16 custom-text-secondary">
                        <Tag className="h-16 w-16 mx-auto custom-text-accent opacity-30 mb-4" />
                        <h3 className="chakra text-xl font-bold custom-text-primary">
                            No Coupons Available
                        </h3>
                        <p className="mt-2 text-sm">
                            Start by creating your first coupon!
                        </p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {coupons.map((coupon) => (
                            <div
                                key={coupon._id}
                                className="custom-bg-secondary rounded-xl shadow-lg p-6 border border-[var(--bg-accent)]/10 hover:shadow-xl transition-shadow duration-300"
                            >
                                <div className="flex justify-between items-center mb-4">
                                    <div className="flex items-center gap-2">
                                        <Tag className="h-5 w-5 custom-text-accent" />
                                        <h3 className="chakra font-mono text-lg font-bold custom-text-primary">
                                            {coupon.code}
                                        </h3>
                                    </div>
                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => handleEdit(coupon)}
                                            className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-sm hover:opacity-90"
                                            title="Edit coupon"
                                        >
                                            <Edit2 size={14} />
                                        </button>
                                        <button
                                            onClick={() => handleDelete(coupon._id, coupon.code)}
                                            className="btn btn-sm text-red-500 rounded-lg flex items-center gap-2 text-sm hover:bg-red-50 dark:hover:bg-red-900/10"
                                            title="Delete coupon"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </div>
                                </div>
                                <div className="inline-block bg-[var(--bg-accent)]/10 text-[var(--text-accent)] rounded-lg px-3 py-1 text-sm font-semibold mb-3">
                                    {coupon.discountAmount}% OFF
                                </div>
                                <p className="text-sm custom-text-secondary mb-4 line-clamp-2">
                                    {coupon.description}
                                </p>
                                <div className="flex items-center gap-2 text-sm custom-text-secondary mb-3">
                                    <Calendar className="h-4 w-4" />
                                    <span>
                                        Expires: {new Date(coupon.expiryDate).toLocaleDateString()}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center text-sm border-t border-[var(--bg-accent)]/20 pt-3">
                                    <span className="custom-text-secondary">Status</span>
                                    <span
                                        className={`px-2 py-1 text-xs font-medium rounded-full ${
                                            isExpired(coupon.expiryDate)
                                                ? 'bg-red-100 text-red-700'
                                                : 'bg-green-100 text-green-700'
                                        }`}
                                    >
                                        {isExpired(coupon.expiryDate) ? 'Expired' : 'Active'}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ManageCoupons;