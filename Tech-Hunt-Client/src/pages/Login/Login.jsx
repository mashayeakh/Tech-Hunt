import { useContext, useState } from "react";
import { AuthContext } from "../../providers/AuthProvider";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import Swal from "sweetalert2";
import withReactContent from "sweetalert2-react-content";
import SocialLogin from "../../components/SocialLogin/SocialLogin";
import useAxiosSecure from "../../hooks/useAxiosSecure";

const MySwal = withReactContent(Swal);

const Login = () => {
    const { signIn } = useContext(AuthContext);
    const axiosSecure = useAxiosSecure();
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();
    const from = location.state?.from?.pathname || "/";

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        const form = e.target;
        const email = form.email.value;
        const password = form.password.value;

        try {
            const result = await signIn(email, password);
            const user = result.user;

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
                title: "Login successful!",
                showConfirmButton: false,
                timer: 1500
            });
            navigate(from, { replace: true });
        } catch (error) {
            let errorMessage = "Failed to login. Please try again.";
            if (error.code === "auth/invalid-credential") {
                errorMessage = "Email or password incorrect.";
            } else if (error.code === "auth/too-many-requests") {
                errorMessage = "Too many attempts. Try again later.";
            }

            MySwal.fire({
                position: "top-end",
                icon: "error",
                title: errorMessage,
                showConfirmButton: false,
                timer: 1500
            });
            console.error('Login error:', error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="custom-bg-primary min-h-screen flex items-center justify-center py-12 font-inter">
            <Helmet>
                <title>Login | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-md">
                <div className="custom-bg-secondary rounded-xl shadow-lg p-8">
                    <h1 className="chakra text-3xl font-bold custom-text-primary text-center mb-8">Login</h1>
                    <form onSubmit={handleLogin} className="space-y-6">
                        <div className="space-y-2">
                            <label className="text-sm custom-text-primary font-medium">Email</label>
                            <input
                                type="email"
                                name="email"
                                placeholder="Enter your email"
                                className="w-full px-4 py-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-sm custom-text-primary font-medium">Password</label>
                            <div className="relative">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    name="password"
                                    placeholder="Enter your password"
                                    className="w-full px-4 py-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                    required
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute top-1/2 right-3 transform -translate-y-1/2 text-[var(--bg-accent)]"
                                >
                                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                </button>
                            </div>
                            <Link to="#" className="text-xs custom-text-accent hover:underline">Forgot password?</Link>
                        </div>
                        <button
                            type="submit"
                            disabled={isLoading}
                            className="w-full px-4 py-2 custom-bg-accent text-white rounded-lg hover:opacity-90 flex items-center justify-center gap-2 text-sm disabled:opacity-50 tooltip tooltip-bottom"
                            data-tip="Log in to your account"
                        >
                            {isLoading ? (
                                <Loader2 size={16} className="animate-spin" />
                            ) : (
                                "Login"
                            )}
                        </button>
                    </form>
                    <div className="text-center mt-6">
                        <p className="text-sm custom-text-secondary">
                            New here?{" "}
                            <Link to="/signup" className="custom-text-accent hover:underline">
                                Create an Account
                            </Link>
                        </p>
                    </div>
                    <SocialLogin />
                </div>
            </div>
        </div>
    );
};

export default Login;