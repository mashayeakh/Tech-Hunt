import { useState, useEffect } from "react";
import useAxiosPublic from "../../hooks/useAxiosPublic";
import Swal from "sweetalert2";
import useAuth from "../../hooks/useAuth";
import { Helmet } from "react-helmet-async";
import { useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";

const Profile = () => {
    const { user, updateUserProfile } = useAuth();
    const navigate = useNavigate();
    const [isEditing, setIsEditing] = useState(false);
    const [loading, setLoading] = useState(false);
    const [mongoUser, setMongoUser] = useState(null);
    const axiosPublic = useAxiosPublic();

    const [formData, setFormData] = useState({
        name: user?.displayName || "",
        photoURL: user?.photoURL || "",
    });

    useEffect(() => {
        const fetchMongoUser = async () => {
            try {
                const response = await axiosPublic.get(`/users/${user?.email}`);
                setMongoUser(response.data);
                if (response.data) {
                    setFormData({
                        name: response.data.name || user?.displayName || "",
                        photoURL: response.data.photoURL || user?.photoURL || "",
                    });
                }
            } catch (error) {
                console.error("Error fetching user data:", error);
            }
        };

        if (user?.email) {
            fetchMongoUser();
        }
    }, [user, axiosPublic]);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
        }));
    };

    const handleSubscribe = () => {
        navigate("/dashboard/payment");
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);

        try {
            await updateUserProfile(formData.name, formData.photoURL);

            const updatedUserData = {
                name: formData.name,
                photoURL: formData.photoURL,
                email: user.email,
                lastUpdated: new Date(),
            };

            if (mongoUser) {
                await axiosPublic.patch(`/users/${user.email}`, updatedUserData);
            } else {
                await axiosPublic.post("/users", updatedUserData);
            }

            Swal.fire({
                position: "top-end",
                icon: "success",
                title: "Profile updated successfully!",
                showConfirmButton: false,
                timer: 1500,
            });
            setIsEditing(false);

            const response = await axiosPublic.get(`/users/${user.email}`);
            setMongoUser(response.data);
        } catch (error) {
            console.error("Error updating profile:", error);
            Swal.fire({
                icon: "error",
                title: "Error",
                text: "Failed to update profile",
            });
        } finally {
            setLoading(false);
        }
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString("en-US", {
            year: "numeric",
            month: "long",
            day: "numeric",
        });
    };

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>My Profile | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <div className="custom-bg-secondary rounded-xl shadow-lg p-8 max-w-lg mx-auto">
                    {/* Profile Header */}
                    <div className="flex flex-col items-center space-y-4">
                        {user?.photoURL ? (
                            <img
                                src={isEditing ? formData.photoURL : (mongoUser?.photoURL || user.photoURL)}
                                alt="User"
                                className="w-28 h-28 rounded-full object-cover border-4 border-[var(--bg-accent)]/30 shadow-lg"
                            />
                        ) : (
                            <div className="w-28 h-28 rounded-full bg-[var(--bg-accent)]/10 flex items-center justify-center text-4xl custom-text-accent font-medium">
                                {user?.displayName?.charAt(0).toUpperCase() || "?"}
                            </div>
                        )}
                        <h1 className="chakra text-3xl font-bold custom-text-primary">
                            Welcome, {isEditing ? formData.name : (mongoUser?.name || user?.displayName || "Guest")}!
                        </h1>
                        <p className="custom-text-secondary text-sm">{user?.email}</p>

                        {/* Membership Status and Subscribe Button */}
                        <div className="flex flex-col items-center space-y-2 mt-4">
                            {mongoUser?.membershipStatus === "active" ? (
                                <div className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-accent)]/10 custom-text-accent rounded-full">
                                    <Shield className="w-5 h-5" />
                                    <span className="font-medium">Premium Member</span>
                                </div>
                            ) : (
                                <>
                                    <div className="px-4 py-1 border border-[var(--bg-accent)]/20 rounded-full text-sm custom-text-secondary">
                                        Free Member
                                    </div>
                                    <button
                                        onClick={handleSubscribe}
                                        className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90 transition-opacity"
                                    >
                                        Subscribe to Premium
                                    </button>
                                </>
                            )}
                        </div>
                    </div>

                    {/* Profile Form */}
                    <div className="mt-6 pt-6 border-t border-[var(--bg-accent)]/20">
                        {isEditing ? (
                            <form onSubmit={handleSubmit} className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Name
                                    </label>
                                    <input
                                        type="text"
                                        name="name"
                                        value={formData.name}
                                        onChange={handleChange}
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        required
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Photo URL
                                    </label>
                                    <input
                                        type="text"
                                        name="photoURL"
                                        value={formData.photoURL}
                                        onChange={handleChange}
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                    />
                                </div>
                                <div className="flex gap-4 justify-end">
                                    <button
                                        type="button"
                                        onClick={() => {
                                            setIsEditing(false);
                                            setFormData({
                                                name: mongoUser?.name || user?.displayName || "",
                                                photoURL: mongoUser?.photoURL || user?.photoURL || "",
                                            });
                                        }}
                                        className="btn btn-sm custom-bg-secondary custom-text-primary rounded-lg text-sm hover:bg-[var(--bg-accent)]/10"
                                        disabled={loading}
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                                        disabled={loading}
                                    >
                                        {loading ? "Saving..." : "Save Changes"}
                                    </button>
                                </div>
                            </form>
                        ) : (
                            <div className="space-y-4">
                                <h3 className="chakra text-lg font-bold custom-text-primary">
                                    Your Profile Information
                                </h3>
                                <ul className="space-y-2 custom-text-secondary text-sm">
                                    <li className="flex justify-between">
                                        <span>Name:</span>
                                        <span>{mongoUser?.name || user?.displayName || "Not provided"}</span>
                                    </li>
                                    <li className="flex justify-between">
                                        <span>Email:</span>
                                        <span>{user?.email}</span>
                                    </li>
                                    <li className="flex justify-between">
                                        <span>Last Updated:</span>
                                        <span>
                                            {mongoUser?.lastUpdated ? formatDate(mongoUser.lastUpdated) : "Never"}
                                        </span>
                                    </li>
                                    <li className="flex justify-between">
                                        <span>Membership Status:</span>
                                        <span
                                            className={
                                                mongoUser?.membershipStatus === "active"
                                                    ? "custom-text-accent font-medium"
                                                    : ""
                                            }
                                        >
                                            {mongoUser?.membershipStatus === "active" ? "Premium" : "Free Plan"}
                                        </span>
                                    </li>
                                    {mongoUser?.membershipStatus === "active" && (
                                        <li className="flex justify-between">
                                            <span>Member Since:</span>
                                            <span>{formatDate(mongoUser.subscriptionDate)}</span>
                                        </li>
                                    )}
                                </ul>
                                <div className="text-center">
                                    <button
                                        onClick={() => setIsEditing(true)}
                                        className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                                    >
                                        Edit Profile
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Profile;