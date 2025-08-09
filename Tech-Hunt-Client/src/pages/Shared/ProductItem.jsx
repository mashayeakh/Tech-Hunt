/* eslint-disable react/prop-types */
import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaClock } from "react-icons/fa6";
import { FiExternalLink } from "react-icons/fi";
import { Loader2, ChevronUpCircle } from "lucide-react";
import useAuth from "../../hooks/useAuth";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import useUpvote from "../../hooks/useUpvote";
import useProducts from "../../hooks/useProducts";
import Swal from "sweetalert2";

const ProductItem = ({ product }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { user } = useAuth();
    const axiosSecure = useAxiosSecure();
    const [upvote, refetch] = useUpvote();
    const [, refetchProducts] = useProducts();
    // Fix: Use product.upvotes for consistency with backend and original code
    const [currentUpvotes, setCurrentUpvotes] = useState(product.upvotes || 0);
    const [isUpvoted, setIsUpvoted] = useState(false);
    const [isUpvoting, setIsUpvoting] = useState(false);

    const { _id, productImage, productName, externalLink, tags, ownerName, ownerEmail, description, timestamp } = product;

    const isOwner = user?.email === ownerEmail;

    // Format date and time
    const formatDateTime = (timestamp) => {
        const date = new Date(timestamp);
        return date.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric' 
        });
    };

    const formattedDate = timestamp ? formatDateTime(timestamp) : 'N/A';

    useEffect(() => {
        if (upvote) {
            setIsUpvoted(upvote.some(item => item.productId === _id));
        }
    }, [upvote, _id]);

    const handleUpvoteProcess = async () => {
        if (isUpvoting || isOwner) return;

        try {
            setIsUpvoting(true);
            
            if (isUpvoted) {
                setIsUpvoted(false);
                setCurrentUpvotes(prev => prev - 1);

                const existingUpvote = upvote.find(item => item.productId === _id);
                const res = await axiosSecure.delete(`/upvotes/${existingUpvote._id}`);
                
                if (res.data.deletedCount > 0) {
                    Promise.all([refetch(), refetchProducts()]);
                    Swal.fire({
                        position: "top-end",
                        icon: "success",
                        title: `Upvote removed from ${productName}`,
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            } else {
                setIsUpvoted(true);
                setCurrentUpvotes(prev => prev + 1);

                const upvoteItem = {
                    productId: _id,
                    email: user.email,
                    productName,
                    productImage,
                    timestamp: new Date().toISOString()
                };

                const res = await axiosSecure.post('/upvotes', upvoteItem);
                
                if (res.data.insertedId) {
                    Promise.all([refetch(), refetchProducts()]);
                    Swal.fire({
                        position: "top-end",
                        icon: "success",
                        title: `${productName} upvoted`,
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            }
        } finally {
            setIsUpvoting(false);
        }
    };

    const handleUpvote = () => {
        if (!user?.email) {
            localStorage.setItem('pendingUpvote', _id);
            Swal.fire({
                title: "Login Required",
                text: "Please login to upvote this tech!",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "var(--bg-accent)",
                cancelButtonColor: "#d33",
                confirmButtonText: "Login"
            }).then((result) => {
                if (result.isConfirmed) {
                    navigate('/login', { state: { from: location } });
                } else {
                    localStorage.removeItem('pendingUpvote');
                }
            });
            return;
        }

        handleUpvoteProcess();
    };

    return (
        <div className="custom-bg-secondary rounded-xl shadow-lg p-6 flex flex-col h-full font-inter">
            <div className="flex flex-col gap-4 flex-1">
                <div className="flex gap-4">
                    <img
                        src={productImage}
                        alt={productName}
                        className="w-20 h-20 object-contain rounded-lg"
                    />
                    <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                            <Link
                                to={`/product/${_id}`}
                                className="chakra text-lg font-bold custom-text-primary hover:custom-text-accent transition-colors duration-200 truncate"
                            >
                                {productName}
                            </Link>
                            <a 
                                href={externalLink}
                                className="custom-text-secondary hover:custom-text-accent transition-colors duration-200 flex-shrink-0"
                                target="_blank"
                                rel="noopener noreferrer"
                                aria-label="Visit external link"
                            >
                                <FiExternalLink className="text-sm" />
                            </a>
                        </div>
                        <p className="custom-text-secondary text-sm line-clamp-2 mb-3">{description}</p>
                        <div className="flex flex-wrap gap-2 mb-3">
                            {tags.map((tag, index) => (
                                <span
                                    key={index}
                                    className="px-2 py-1 text-xs font-medium rounded-full bg-[var(--bg-accent)]/10 custom-text-accent"
                                >
                                    {tag}
                                </span>
                            ))}
                        </div>
                        {timestamp && (
                            <div className="flex items-center gap-2 text-xs custom-text-secondary">
                                <FaClock className="custom-text-accent" />
                                <span>Added on {formattedDate}</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--bg-accent)]/20 flex justify-between items-center">
                <span className="flex items-center gap-2 text-xs custom-text-secondary">
                    <div className="w-5 h-5 rounded-full bg-[var(--bg-accent)]/20 flex items-center justify-center text-xs custom-text-accent font-medium">
                        {ownerName.charAt(0).toUpperCase()}
                    </div>
                    <span>by {ownerName}</span>
                </span>
                <button
                    onClick={handleUpvote}
                    disabled={isOwner || isUpvoting}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all duration-300 text-sm font-inter
                        ${isUpvoted 
                            ? 'custom-bg-accent text-white' 
                            : 'bg-[var(--bg-accent)]/10 custom-text-accent hover:custom-bg-accent hover:text-white'} 
                        ${isOwner ? 'opacity-50 cursor-not-allowed' : 'hover:scale-105'} tooltip tooltip-bottom`}
                    data-tip={isOwner ? "Cannot upvote your own product" : isUpvoted ? "Remove upvote" : "Upvote product"}
                >
                    {isUpvoting ? (
                        <Loader2 size={16} className="animate-spin" />
                    ) : (
                        <ChevronUpCircle size={16} />
                    )}
                    <span className="font-bold">{currentUpvotes}</span>
                </button>
            </div>
        </div>
    );
};

export default ProductItem;