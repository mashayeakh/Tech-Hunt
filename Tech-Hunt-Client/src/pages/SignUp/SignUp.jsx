import { useContext, useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { Helmet } from "react-helmet-async";
import Swal from "sweetalert2";
import withReactContent from "sweetalert2-react-content";
import { AuthContext } from "../../providers/AuthProvider";
import useAxiosPublic from "../../hooks/useAxiosPublic";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import SocialLogin from "../../components/SocialLogin/SocialLogin";

const MySwal = withReactContent(Swal);

const SignUp = () => {
    const axiosPublic = useAxiosPublic();
    const axiosSecure = useAxiosSecure();
    const { createUser, updateUserProfile } = useContext(AuthContext);
    const { register, handleSubmit, reset } = useForm();
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const validatePassword = {
        hasMinLength: password.length >= 6,
        hasNumber: /\d/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasUppercase: /[A-Z]/.test(password),
    };

    const isPasswordValid =
        validatePassword.hasMinLength &&
        validatePassword.hasNumber &&
        validatePassword.hasLowercase &&
        validatePassword.hasUppercase;

    const onSubmit = async (data) => {
        if (!isPasswordValid) {
            MySwal.fire({
                position: "top-end",
                icon: "error",
                title: "Password does not meet requirements",
                showConfirmButton: false,
                timer: 1500
            });
            return;
        }

        setIsLoading(true);
        try {
            const result = await createUser(data.email, data.password);
            const loggedUser = result.user;

            await updateUserProfile(data.name, data.photoURL);

            const userInfo = {
                name: data.name,
                email: data.email
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
                        email: loggedUser.email,
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
                title: "Account created successfully!",
                showConfirmButton: false,
                timer: 1500
            });
            reset();
            navigate('/');
        } catch (error) {
            let errorMessage = "Failed to create account.";
            if (error.code === "auth/email-already-in-use") {
                errorMessage = "Email already in use.";
            } else if (error.code === "auth/invalid-email") {
                errorMessage = "Invalid email address.";
            } else if (error.code === "auth/weak-password") {
                errorMessage = "Password is too weak.";
            }

            MySwal.fire({
                position: "top-end",
                icon: "error",
                title: errorMessage,
                showConfirmButton: false,
                timer: 1500
            });
            console.error('Signup error:', error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="custom-bg-primary min-h-screen flex items-center justify-center py-12 font-inter">
            <Helmet>
                <title>Signup | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-md">
                <div className="custom-bg-secondary rounded-xl shadow-lg p-8">
                    <h1 className="chakra text-3xl font-bold custom-text-primary text-center mb-8">Sign Up</h1>
                    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                        <div className="space-y-2">
                            <label className="text-sm custom-text-primary font-medium">Name</label>
                            <input
                                type="text"
                                {...register("name")}
                                placeholder="Enter your name"
                                className="w-full px-4 py-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-sm custom-text-primary font-medium">Photo URL</label>
                            <input
                                type="text"
                                {...register("photoURL")}
                                placeholder="Enter your photo URL"
                                className="w-full px-4 py-2 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm"
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-sm custom-text-primary font-medium">Email</label>
                            <input
                                type="email"
                                {...register("email")}
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
                                    {...register("password")}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Enter your password"
                                    className={`w-full px-4 py-2 custom-bg-primary custom-text-primary border rounded-lg focus:border-[var(--bg-accent)] outline-none text-sm ${isPasswordValid ? "border-green-500" : "border-[var(--bg-accent)]/20"}`}
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
                            <div className="mt-2 text-xs space-y-1">
                                <p className={validatePassword.hasMinLength ? "text-green-500" : "text-gray-400"}>
                                    ✓ At least 6 characters
                                </p>
                                <p className={validatePassword.hasNumber ? "text-green-500" : "text-gray-400"}>
                                    ✓ At least one number
                                </p>
                                <p className={validatePassword.hasLowercase ? "text-green-500" : "text-gray-400"}>
                                    ✓ At least one lowercase letter
                                </p>
                                <p className={validatePassword.hasUppercase ? "text-green-500" : "text-gray-400"}>
                                    ✓ At least one uppercase letter
                                </p>
                            </div>
                        </div>
                        <button
                            type="submit"
                            disabled={isLoading}
                            className="w-full px-4 py-2 custom-bg-accent text-white rounded-lg hover:opacity-90 flex items-center justify-center gap-2 text-sm disabled:opacity-50 tooltip tooltip-bottom"
                            data-tip="Create your account"
                        >
                            {isLoading ? (
                                <Loader2 size={16} className="animate-spin" />
                            ) : (
                                "Sign Up"
                            )}
                        </button>
                    </form>
                    <div className="text-center mt-6">
                        <p className="text-sm custom-text-secondary">
                            Already have an account?{" "}
                            <Link to="/login" className="custom-text-accent hover:underline">
                                Login
                            </Link>
                        </p>
                    </div>
                    <SocialLogin />
                </div>
            </div>
        </div>
    );
};

export default SignUp;