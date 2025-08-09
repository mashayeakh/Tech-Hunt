import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { FaCircleChevronUp, FaClock, FaRegComment } from "react-icons/fa6";
import { FiExternalLink, FiShare2, FiFlag } from "react-icons/fi";
import { Loader2 } from "lucide-react"; // Import Loader2 from lucide-react
import ReactStars from 'react-awesome-stars-rating';
import useAuth from '../../hooks/useAuth';
import useAxiosSecure from '../../hooks/useAxiosSecure';
import useUpvote from '../../hooks/useUpvote';
import useProducts from '../../hooks/useProducts';
import Swal from 'sweetalert2';
import { Helmet } from 'react-helmet-async';

const ProductDetails = () => {
    const { id } = useParams();
    const { user } = useAuth();
    const axiosSecure = useAxiosSecure();
    const [upvote, refetch] = useUpvote();
    const [products, refetchProducts] = useProducts();
    const [product, setProduct] = useState(null);
    const [reviews, setReviews] = useState([]);
    const [rating, setRating] = useState(0);
    const [reviewText, setReviewText] = useState('');
    const [loading, setLoading] = useState(true);
    const [currentUpvotes, setCurrentUpvotes] = useState(0);
    const [isUpvoting, setIsUpvoting] = useState(false);
    const [similarProducts, setSimilarProducts] = useState([]);

    // Fetch product details
    useEffect(() => {
        const fetchProduct = async () => {
            try {
                const response = await axiosSecure.get(`/product/${id}`);
                setProduct(response.data);
                setCurrentUpvotes(response.data.upvotes || 0);
                setLoading(false);
            } catch (error) {
                console.error('Error fetching product:', error);
                setLoading(false);
            }
        };

        fetchProduct();
    }, [id, axiosSecure]);

    // Fetch reviews
    useEffect(() => {
        const fetchReviews = async () => {
            try {
                const response = await axiosSecure.get(`/reviews/${id}`);
                setReviews(response.data);
            } catch (error) {
                console.error('Error fetching reviews:', error);
            }
        };

        fetchReviews();
    }, [id, axiosSecure]);

    // Find similar products based on tags
    useEffect(() => {
        if (product && products.length > 0) {
            const similar = products
                .filter(p =>
                    p._id !== id &&
                    p.tags.some(tag => product.tags.includes(tag))
                )
                .slice(0, 4);
            setSimilarProducts(similar);
        }
    }, [product, products, id]);

    const hasUpvoted = upvote.some(item => item.productId === id);
    const isOwner = user?.email === product?.ownerEmail;

    const handleUpvote = () => {
        if (isUpvoting || isOwner) return;

        setIsUpvoting(true);
        const existingUpvote = upvote.find(item => item.productId === id);

        if (existingUpvote) {
            axiosSecure.delete(`/upvotes/${existingUpvote._id}`)
                .then(res => {
                    if (res.data.deletedCount > 0) {
                        setCurrentUpvotes(prev => prev - 1);
                        refetch();
                        refetchProducts();
                        Swal.fire({
                            position: "top-end",
                            icon: "success",
                            title: `Upvote removed from ${product.productName}`,
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                })
                .finally(() => setIsUpvoting(false));
        } else {
            const upvoteItem = {
                productId: id,
                email: user.email,
                productName: product.productName,
                productImage: product.productImage,
                timestamp: new Date().toISOString()
            }
            axiosSecure.post('/upvotes', upvoteItem)
                .then(res => {
                    if (res.data.insertedId) {
                        setCurrentUpvotes(prev => prev + 1);
                        refetch();
                        refetchProducts();
                        Swal.fire({
                            position: "top-end",
                            icon: "success",
                            title: `${product.productName} upvoted`,
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                })
                .finally(() => setIsUpvoting(false));
        }
    };

    const formatDateTime = (timestamp) => {
        const date = new Date(timestamp);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    const handleReport = async () => {
        try {
            const { value: reportReason } = await Swal.fire({
                title: 'Report Product',
                input: 'textarea',
                inputLabel: 'Reason for reporting',
                inputPlaceholder: 'Type your reason here...',
                inputValidator: (value) => {
                    if (!value) {
                        return 'You need to write something!';
                    }
                },
                showCancelButton: true,
                confirmButtonColor: 'var(--bg-accent)',
                cancelButtonColor: '#d1d5db',
                confirmButtonText: 'Submit Report'
            });

            if (reportReason) {
                const reportData = {
                    productId: id,
                    productName: product.productName,
                    reportedBy: user.email,
                    reporterName: user.displayName,
                    productImage: product.productImage,
                    ownerEmail: product.ownerEmail,
                    ownerName: product.ownerName,
                    productTimestamp: product.createdAt,
                    reason: reportReason,
                    timestamp: new Date()
                };

                const response = await axiosSecure.post('/reports', reportData);

                if (response.data.insertedId) {
                    await Swal.fire({
                        position: "center",
                        icon: "success",
                        title: "Report submitted successfully",
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            }
        } catch (error) {
            console.error('Error submitting report:', error);
            Swal.fire({
                icon: "error",
                title: "Error",
                text: "Failed to submit report. Please try again."
            });
        }
    };

    const handleReviewSubmit = async (e) => {
        e.preventDefault();

        if (rating === 0) {
            Swal.fire('Error', 'Please select a rating before submitting', 'error');
            return;
        }

        const reviewData = {
            productId: id,
            reviewerName: user.displayName,
            reviewerImage: user.photoURL,
            rating: rating,
            description: reviewText,
            timestamp: new Date()
        };

        try {
            await axiosSecure.post('/reviews', reviewData);
            setReviews([...reviews, reviewData]);
            setReviewText('');
            setRating(0);
            Swal.fire('Success', 'Review posted successfully!', 'success');
        } catch (error) {
            Swal.fire('Error', 'Failed to post review.', 'error');
        }
    };

    const handleShare = () => {
        navigator.clipboard.writeText(window.location.href);
        Swal.fire({
            position: "top-end",
            icon: "success",
            title: "Link copied to clipboard!",
            showConfirmButton: false,
            timer: 1500
        });
    };

    if (loading) {
        return (
            <div className="flex justify-center items-center min-h-screen custom-bg-primary">
                <div className="w-12 h-12 border-2 border-t-transparent border-[var(--bg-accent)] rounded-full animate-spin"></div>
            </div>
        );
    }

    if (!product) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[50vh] custom-bg-primary custom-text-primary">
                <h2 className="chakra text-xl font-bold">Product Not Found</h2>
                <p className="custom-text-secondary mt-2">The product you're looking for doesn't exist or has been removed.</p>
                <Link to="/" className="mt-4 px-4 py-2 custom-bg-accent text-white rounded-md hover:opacity-90 transition-opacity">
                    Back to Home
                </Link>
            </div>
        );
    }

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>{product.productName} | Tech Hunt</title>
            </Helmet>

            <div className="container mx-auto px-4 max-w-5xl">
                {/* Main Product Section */}
                <div className="custom-bg-secondary rounded-xl shadow-lg p-6 mb-8">
                    <div className="flex flex-col gap-3">
                        {/* Product Header */}
                        <div className="flex flex-col sm:flex-row gap-6">
                            <div className="w-full sm:w-1/3">
                                <img
                                    src={product.productImage}
                                    alt={product.productName}
                                    className="w-full h-48 object-contain rounded-lg"
                                />
                            </div>
                            <div className="flex-1">
                                <h1 className="chakra text-3xl font-bold custom-text-primary mb-3">{product.productName}</h1>
                                <p className="custom-text-secondary mb-4 leading-relaxed">{product.description}</p>
                                <div className="flex flex-wrap gap-2 mb-4">
                                    {product.tags.map((tag, index) => (
                                        <span
                                            key={index}
                                            className="px-2 py-1 text-xs font-medium rounded-full bg-[var(--bg-accent)]/10 custom-text-accent"
                                        >
                                            {tag}
                                        </span>
                                    ))}
                                </div>
                                <div className="flex items-center gap-2 text-sm custom-text-secondary mb-4">
                                    <div className="w-6 h-6 rounded-full bg-[var(--bg-accent)]/20 flex items-center justify-center text-xs custom-text-accent font-medium">
                                        {product.ownerName?.charAt(0).toUpperCase() || '?'}
                                    </div>
                                    <span>{product.ownerName}</span>
                                    <span className="mx-2">•</span>
                                    <FaClock className="custom-text-accent text-sm" />
                                    <span>{product.timestamp ? formatDateTime(product.timestamp) : 'Date not available'}</span>
                                </div>
                                <div className=''>
                                    <button
                                        onClick={handleUpvote}
                                        disabled={isOwner || isUpvoting}
                                        className={`flex items-center gap-2 btn btn-lg btn-outline rounded-lg shadow-md transition-all duration-300 
                                    ${hasUpvoted
                                                ? 'custom-bg-accent text-white'
                                                : 'bg-[var(--bg-accent)]/5 custom-text-accent hover:custom-bg-accent hover:text-white'} 
                                    ${isOwner ? 'opacity-50 cursor-not-allowed' : 'hover:scale-105'}`}
                                    >
                                        {isUpvoting ? (
                                            <Loader2 size={18} className="animate-spin" />
                                        ) : (
                                            <FaCircleChevronUp className="text-xl" />
                                        )}
                                        <span className="font-bold">{currentUpvotes}</span>
                                        <span className="font-medium">{hasUpvoted ? 'Upvoted' : 'Upvote'}</span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Action Buttons */}
                        <div className="flex flex-wrap gap-3">
                            <a
                                href={product.externalLink}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="btn btn-sm custom-bg-secondary custom-text-primary rounded-lg flex items-center gap-2 text-sm hover:bg-[var(--bg-accent)]/10"
                            >
                                <FiExternalLink size={14} /> Visit Website
                            </a>
                            <button
                                onClick={handleShare}
                                className="btn btn-sm custom-bg-secondary custom-text-primary rounded-lg flex items-center gap-2 text-sm hover:bg-[var(--bg-accent)]/10"
                            >
                                <FiShare2 size={14} className="custom-text-accent" /> Share
                            </button>
                            <button
                                onClick={handleReport}
                                className="btn btn-sm custom-bg-secondary text-red-500 rounded-lg flex items-center gap-2 text-sm hover:bg-red-50 dark:hover:bg-red-900/10"
                            >
                                <FiFlag size={14} /> Report
                            </button>

                        </div>
                    </div>
                </div>

                {/* Reviews Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    {/* Write Review */}
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6">
                        <h2 className="chakra text-xl font-bold custom-text-primary mb-4">Write a Review</h2>
                        <form onSubmit={handleReviewSubmit} className="space-y-4">
                            <div className="flex items-center gap-3">
                                <img
                                    src={user.photoURL}
                                    alt={user.displayName}
                                    className="w-10 h-10 object-cover rounded-full border border-[var(--bg-accent)]/30"
                                />
                                <div>
                                    <p className="font-medium custom-text-primary text-sm">{user.displayName}</p>
                                    <ReactStars
                                        value={rating}
                                        onChange={value => setRating(value)}
                                        size={20}
                                        isHalf={true}
                                        primaryColor="var(--bg-accent)"
                                        className="flex gap-1 mt-1"
                                    />
                                </div>
                            </div>
                            <textarea
                                value={reviewText}
                                onChange={(e) => setReviewText(e.target.value)}
                                className="w-full h-24 p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all resize-none text-sm"
                                placeholder="Share your thoughts about this product..."
                                required
                            />
                            <button
                                type="submit"
                                className="w-full px-4 py-2 custom-bg-accent text-white rounded-lg hover:opacity-90 text-sm"
                            >
                                Post Review
                            </button>
                        </form>
                    </div>

                    {/* Reviews List */}
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6">
                        <div className="flex items-center gap-2 mb-4">
                            <FaRegComment className="custom-text-accent" />
                            <h2 className="chakra text-xl font-bold custom-text-primary">Customer Reviews</h2>
                        </div>
                        <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                            {reviews.length > 0 ? (
                                reviews
                                    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                                    .map((review, index) => (
                                        <div
                                            key={index}
                                            className="p-4 rounded-lg custom-bg-primary border border-[var(--bg-accent)]/10"
                                        >
                                            <div className="flex items-center gap-3 mb-2">
                                                <img
                                                    src={review.reviewerImage}
                                                    alt={review.reviewerName}
                                                    className="w-8 h-8 rounded-full border border-[var(--bg-accent)]/30"
                                                />
                                                <div className="flex-1">
                                                    <div className="flex justify-between">
                                                        <h3 className="font-medium custom-text-primary text-sm">{review.reviewerName}</h3>
                                                        <span className="text-xs custom-text-secondary">
                                                            {new Date(review.timestamp).toLocaleDateString()}
                                                        </span>
                                                    </div>
                                                    <ReactStars
                                                        value={review.rating}
                                                        isEdit={false}
                                                        size={14}
                                                        isHalf={true}
                                                        primaryColor="var(--bg-accent)"
                                                        className="flex gap-1 mt-1"
                                                    />
                                                </div>
                                            </div>
                                            <p className="custom-text-secondary text-sm">{review.description}</p>
                                        </div>
                                    ))
                            ) : (
                                <div className="text-center py-6 custom-text-secondary">
                                    <FaRegComment className="text-2xl opacity-30 mx-auto mb-2" />
                                    <p className="text-sm">No reviews yet. Be the first to share your thoughts!</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ProductDetails;