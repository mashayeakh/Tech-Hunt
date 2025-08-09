import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import Swal from "sweetalert2";
import { Helmet } from "react-helmet-async";

const CouponsPage = () => {
    const [coupons, setCoupons] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchCoupons = async () => {
            try {
                const response = await fetch("https://tech-hunt-server-two.vercel.app/coupons");
                const data = await response.json();
                setCoupons(data);
                setLoading(false);
            } catch (error) {
                console.error("Error fetching coupons:", error);
                setLoading(false);
            }
        };

        fetchCoupons();
    }, []);

    const handleCopyCode = (code) => {
        navigator.clipboard.writeText(code);
        Swal.fire({
            position: "top-end",
            icon: "success",
            title: "Coupon code copied to clipboard!",
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

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Coupons | Tech Hunt</title>
            </Helmet>

            <div className="container mx-auto px-4 max-w-5xl">
                <div className="text-center mb-12">
                    <span className="inline-block px-4 py-1 rounded-full bg-[var(--bg-accent)]/10 custom-text-accent font-medium text-sm mb-4">
                        EXCLUSIVE OFFERS
                    </span>
                    <h1 className="chakra text-3xl md:text-4xl font-bold custom-text-primary">
                        Available Coupons
                    </h1>
                    <p className="custom-text-secondary mt-3 max-w-lg mx-auto text-sm">
                        Use these coupons during checkout to get amazing discounts on our products
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {coupons.map((coupon) => (
                        <motion.div
                            key={coupon.id}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.3 }}
                            className="custom-bg-secondary rounded-xl shadow-lg p-6 flex flex-col border border-[var(--bg-accent)]/10 hover:shadow-xl transition-shadow duration-300"
                        >
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <span className="p-2 rounded-full bg-[var(--bg-accent)]/10 custom-text-accent">
                                        <svg
                                            xmlns="http://www.w3.org/2000/svg"
                                            className="h-5 w-5"
                                            fill="none"
                                            viewBox="0 0 24 24"
                                            stroke="currentColor"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth="2"
                                                d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"
                                            />
                                        </svg>
                                    </span>
                                    <h2 className="chakra text-xl font-bold custom-text-primary tracking-tight">
                                        {coupon.code}
                                    </h2>
                                </div>
                                <span className="px-3 py-1 bg-[var(--bg-accent)]/10 custom-text-accent rounded-full text-sm font-medium">
                                    {coupon.discountAmount}% OFF
                                </span>
                            </div>

                            <div className="flex-1 space-y-3 mb-6">
                                <p className="custom-text-secondary text-sm">
                                    {coupon.description}
                                </p>
                                <div className="flex items-center text-sm custom-text-secondary">
                                    <svg
                                        xmlns="http://www.w3.org/2000/svg"
                                        className="h-4 w-4 mr-1 custom-text-accent"
                                        fill="none"
                                        viewBox="0 0 24 24"
                                        stroke="currentColor"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth="2"
                                            d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                                        />
                                    </svg>
                                    Valid until:{" "}
                                    {new Date(coupon.expiryDate).toLocaleDateString("en-US", {
                                        year: "numeric",
                                        month: "short",
                                        day: "numeric",
                                    })}
                                </div>
                            </div>

                            <div className="flex items-center justify-between">
                                <button
                                    onClick={() => handleCopyCode(coupon.code)}
                                    className="relative group custom-text-accent text-sm font-medium hover:custom-text-accent transition-colors"
                                >
                                    <span>Click to copy</span>
                                    <span className="absolute -top-8 left-0 opacity-0 group-hover:opacity-100 transition-opacity custom-bg-accent text-white text-xs px-2 py-1 rounded">
                                        Copy code
                                    </span>
                                </button>
                                <Link
                                    to={`/dashboard/payment?coupon=${coupon.code}`}
                                    className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90 transition-opacity"
                                >
                                    Use Now
                                </Link>
                            </div>
                        </motion.div>
                    ))}
                </div>

                {coupons.length === 0 && (
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
                            No Coupons Available
                        </h3>
                        <p className="mt-2 text-sm">
                            Check back later for exclusive deals and offers.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default CouponsPage;