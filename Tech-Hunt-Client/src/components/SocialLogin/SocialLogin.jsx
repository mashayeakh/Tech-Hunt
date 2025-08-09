import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { FcGoogle } from "react-icons/fc";
import useAuth from "../../hooks/useAuth";
import useAxiosPublic from "../../hooks/useAxiosPublic";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import Swal from "sweetalert2";
import withReactContent from "sweetalert2-react-content";

const MySwal = withReactContent(Swal);

const SocialLogin = () => {
    const { googleSignIn } = useAuth();
    const axiosPublic = useAxiosPublic();
    const axiosSecure = useAxiosSecure();
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleGoogleSignIn = async () => {
        setIsLoading(true);
        try {
            const result = await googleSignIn();
            const user = result.user;
            const userInfo = {
                email: user.email,
                name: user.displayName
            };

            await axiosPublic.post('/users', userInfo);

            // Handle pending upvote
            const pendingUpvote = localStorage.getItem('pendingUpvote');
            if (pendingUpvote) {
                try {
                    const productRes = await axiosSecure.get(`/product/${pendingUpvote}`);
                    const product = productRes.data;
                    const upvoteItem = {
                        productId: pendingUpvote,
                        email: user.email,
                        productName: product.productName,
                        productImage: product.productImage,
                        timestamp: new Date().toISOString()
                    };

                    const postRes = await axiosSecure.post('/upvotes', upvoteItem);
                    if (postRes.status === 200 || postRes.status === 201 || postRes.data.insertedId) {
                        await axiosSecure.patch(`/products/${pendingUpvote}/upvote`, { action: 'increment' });
                        MySwal.fire({
                            position: "top-end",
                            icon: "success",
                            title: `${product.productName} upvoted`,
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                    localStorage.removeItem('pendingUpvote');
                } catch (upvoteError) {
                    console.error('Error processing pending upvote:', upvoteError);
                    MySwal.fire({
                        position: "top-end",
                        icon: "error",
                        title: "Failed to process pending upvote",
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            }

            MySwal.fire({
                position: "top-end",
                icon: "success",
                title: "Signed in with Google",
                showConfirmButton: false,
                timer: 1500
            });
            navigate('/');
        } catch (error) {
            console.error('Google sign-in error:', error);
            MySwal.fire({
                position: "top-end",
                icon: "error",
                title: "Failed to sign in with Google",
                showConfirmButton: false,
                timer: 1500
            });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="px-6 pt-4">
            <div className="divider text-xs custom-text-secondary font-inter">Or continue with</div>
            <div className="py-3">
                <button
                    onClick={handleGoogleSignIn}
                    disabled={isLoading}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 custom-bg-primary border border-[var(--bg-accent)]/20 rounded-lg custom-text-primary hover:custom-bg-accent hover:text-white text-sm font-inter transition-all duration-300 disabled:opacity-50 hover:scale-105 shadow-sm tooltip tooltip-bottom"
                    data-tip="Sign in with Google"
                >
                    {isLoading ? (
                        <Loader2 size={16} className="animate-spin" />
                    ) : (
                        <FcGoogle size={16} className="custom-text-accent" />
                    )}
                    Sign in with Google
                </button>
            </div>
        </div>
    );
};

export default SocialLogin;