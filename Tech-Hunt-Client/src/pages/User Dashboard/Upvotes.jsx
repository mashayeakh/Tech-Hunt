import Swal from "sweetalert2";
import useUpvote from "../../hooks/useUpvote";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import { Helmet } from "react-helmet-async";
import { FaRegTrashAlt } from "react-icons/fa";

const Upvotes = () => {
    const [upvote, refetch] = useUpvote();
    const axiosSecure = useAxiosSecure();

    const handleDelete = (id, productName) => {
        Swal.fire({
            title: "Are you sure?",
            text: "You won't be able to revert this!",
            icon: "warning",
            showCancelButton: true,
            confirmButtonColor: "var(--bg-accent)",
            cancelButtonColor: "#d33",
            confirmButtonText: "Yes, delete it!",
        }).then((result) => {
            if (result.isConfirmed) {
                axiosSecure.delete(`/upvotes/${id}`).then((res) => {
                    if (res.data.deletedCount > 0) {
                        refetch();
                        Swal.fire({
                            position: "top-end",
                            icon: "success",
                            title: `Upvote removed from ${productName}`,
                            showConfirmButton: false,
                            timer: 1500,
                        });
                    }
                });
            }
        });
    };

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>My Upvotes | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    My Upvotes: {upvote.length}
                </h2>

                {upvote.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {upvote.map((item, index) => (
                            <div
                                key={item._id}
                                className="custom-bg-secondary rounded-xl shadow-lg p-6 flex flex-col border border-[var(--bg-accent)]/10 hover:shadow-xl transition-shadow duration-300"
                            >
                                <div className="flex gap-4">
                                    <img
                                        src={item.productImage}
                                        alt={item.productName}
                                        className="w-20 h-20 object-contain rounded-lg"
                                    />
                                    <div className="flex-1">
                                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">
                                            {item.productName}
                                        </h3>
                                        <p className="custom-text-secondary text-sm">
                                            Upvoted on{" "}
                                            {new Date(item.timestamp).toLocaleDateString("en-US", {
                                                year: "numeric",
                                                month: "short",
                                                day: "numeric",
                                            })}
                                        </p>
                                    </div>
                                </div>
                                <div className="mt-4 pt-3 border-t border-[var(--bg-accent)]/20 flex justify-end">
                                    <button
                                        onClick={() => handleDelete(item._id, item.productName)}
                                        className="btn btn-sm text-red-500 rounded-lg flex items-center gap-2 text-sm hover:bg-red-50 dark:hover:bg-red-900/10"
                                    >
                                        <FaRegTrashAlt size={14} />
                                        Remove
                                    </button>
                                </div>
                            </div>
                        ))}
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
                            No Upvotes Yet
                        </h3>
                        <p className="mt-2 text-sm">
                            Explore products and upvote your favorites to see them here!
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Upvotes;