import { useEffect, useState } from "react";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import useAuth from "../../hooks/useAuth";
import Swal from "sweetalert2";
import { useForm } from 'react-hook-form';
import { WithContext as ReactTags } from 'react-tag-input';
import { Helmet } from "react-helmet-async";
import { FaRegTrashAlt, FaEdit } from "react-icons/fa";

const MyProducts = () => {
    const [products, setProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const { user } = useAuth();
    const axiosSecure = useAxiosSecure();
    const [editingProduct, setEditingProduct] = useState(null);
    const [tags, setTags] = useState([]);
    const [previewImage, setPreviewImage] = useState('');

    const { register, handleSubmit, setValue, reset, formState: { errors } } = useForm();
    const image_hosting_key = import.meta.env.VITE_IMAGE_HOSTING_KEY;
    const image_hosting_api = `https://api.imgbb.com/1/upload?key=${image_hosting_key}`;

    useEffect(() => {
        const fetchUserProducts = async () => {
            if (user?.email) {
                try {
                    const response = await axiosSecure.get(`/products/user/${user.email}`);
                    setProducts(response.data);
                } catch (error) {
                    console.error('Error fetching user products:', error);
                    Swal.fire({
                        position: "top-end",
                        icon: "error",
                        title: "Failed to load products",
                        text: "Please try again later",
                        showConfirmButton: false,
                        timer: 1500
                    });
                } finally {
                    setLoading(false);
                }
            }
        };

        fetchUserProducts();
    }, [user?.email, axiosSecure]);

    const handleEdit = (product) => {
        setEditingProduct(product);
        setTags(product.tags?.map(tag => tag) || []);
        setPreviewImage(product.productImage);
        reset({
            productName: product.productName,
            description: product.description,
            externalLink: product.externalLink,
            tags: product.tags
        });
    };

    const handleImageChange = async (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setPreviewImage(reader.result);
            };
            reader.readAsDataURL(file);
            setValue('productImage', file);
        }
    };

    const handleAddTag = (tag) => {
        if (!tags.includes(tag.text)) {
            const newTags = [...tags, tag.text];
            setTags(newTags);
            setValue('tags', newTags);
        }
    };

    const handleDeleteTag = (i) => {
        const newTags = tags.filter((_, index) => index !== i);
        setTags(newTags);
        setValue('tags', newTags);
    };

    const handleUpdate = async (data) => {
        try {
            let imageUrl = editingProduct.productImage;

            if (data.productImage?.[0]) {
                const imageFile = new FormData();
                imageFile.append('image', data.productImage[0]);
                const imgbbRes = await axiosSecure.post(image_hosting_api, imageFile, {
                    headers: {
                        'content-type': 'multipart/form-data'
                    }
                });
                if (imgbbRes.data.success) {
                    imageUrl = imgbbRes.data.data.display_url;
                }
            }

            const updatedProduct = {
                productName: data.productName,
                productImage: imageUrl,
                description: data.description,
                externalLink: data.externalLink,
                tags: tags,
            };

            const result = await axiosSecure.patch(`/products/${editingProduct._id}`, updatedProduct);

            if (result.data.modifiedCount > 0) {
                setProducts(products.map(product =>
                    product._id === editingProduct._id
                        ? { ...product, ...updatedProduct }
                        : product
                ));

                setEditingProduct(null);
                Swal.fire({
                    position: "top-end",
                    icon: "success",
                    title: "Product updated successfully!",
                    showConfirmButton: false,
                    timer: 1500
                });
            }
        } catch (error) {
            console.error('Error updating product:', error);
            Swal.fire({
                icon: "error",
                title: "Failed to update product",
                text: "Please try again",
                showConfirmButton: false,
                timer: 1500
            });
        }
    };

    const handleDelete = (id, productName) => {
        Swal.fire({
            title: "Are you sure?",
            text: "You won't be able to revert this!",
            icon: "warning",
            showCancelButton: true,
            confirmButtonColor: "var(--bg-accent)",
            cancelButtonColor: "#d33",
            confirmButtonText: "Yes, delete it!"
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const res = await axiosSecure.delete(`/products/${id}`);
                    if (res.data.deletedCount > 0) {
                        setProducts(products.filter(product => product._id !== id));
                        Swal.fire({
                            position: "top-end",
                            icon: "success",
                            title: `${productName} deleted successfully!`,
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                } catch (error) {
                    console.error('Error deleting product:', error);
                    Swal.fire({
                        icon: "error",
                        title: "Delete Failed",
                        text: error.response?.data?.message || "Failed to delete product",
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            }
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
                <title>My Products | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    My Products: {products.length}
                </h2>

                {products.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {products.map((product, index) => (
                            <div
                                key={product._id}
                                className="custom-bg-secondary rounded-xl shadow-lg p-6 flex flex-col border border-[var(--bg-accent)]/10 hover:shadow-xl transition-shadow duration-300"
                            >
                                <div className="flex gap-4">
                                    <img
                                        src={product.productImage}
                                        alt={product.productName}
                                        className="w-20 h-20 object-contain rounded-lg"
                                    />
                                    <div className="flex-1">
                                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">
                                            {product.productName}
                                        </h3>
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className="px-2 py-1 text-xs font-medium rounded-full bg-[var(--bg-accent)]/10 custom-text-accent">
                                                Upvotes: {product.upvotes || 0}
                                            </span>
                                            <span
                                                className={`px-2 py-1 text-xs font-medium rounded-full ${
                                                    product.status === 'accepted'
                                                        ? 'bg-green-100 text-green-700'
                                                        : product.status === 'rejected'
                                                        ? 'bg-red-100 text-red-700'
                                                        : 'bg-yellow-100 text-yellow-700'
                                                }`}
                                            >
                                                {product.status || 'pending'}
                                            </span>
                                        </div>
                                        <p className="custom-text-secondary text-sm line-clamp-2">
                                            {product.description}
                                        </p>
                                    </div>
                                </div>
                                <div className="mt-4 pt-3 border-t border-[var(--bg-accent)]/20 flex justify-end gap-2">
                                    <button
                                        onClick={() => handleEdit(product)}
                                        className="btn btn-sm custom-bg-accent text-white rounded-lg flex items-center gap-2 text-sm hover:opacity-90"
                                    >
                                        <FaEdit size={14} />
                                        Edit
                                    </button>
                                    <button
                                        onClick={() => handleDelete(product._id, product.productName)}
                                        className="btn btn-sm text-red-500 rounded-lg flex items-center gap-2 text-sm hover:bg-red-50 dark:hover:bg-red-900/10"
                                    >
                                        <FaRegTrashAlt size={14} />
                                        Delete
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
                            No Products Yet
                        </h3>
                        <p className="mt-2 text-sm">
                            Add your first product to showcase it here!
                        </p>
                    </div>
                )}

                {editingProduct && (
                    <dialog className="modal modal-bottom sm:modal-middle" open>
                        <div className="modal-box max-w-3xl custom-bg-secondary p-8 rounded-xl">
                            <h3 className="chakra text-xl font-bold custom-text-primary mb-6">
                                Edit Product
                            </h3>
                            <form onSubmit={handleSubmit(handleUpdate)} className="space-y-6">
                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Product Name
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <input
                                        type="text"
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        {...register('productName', { required: true })}
                                    />
                                    {errors.productName && (
                                        <span className="text-red-500 text-sm mt-1">Product name is required</span>
                                    )}
                                </div>

                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Product Image
                                    </label>
                                    <input
                                        type="file"
                                        accept="image/*"
                                        className="file-input file-input-bordered w-full custom-bg-primary custom-text-primary border-[var(--bg-accent)]/20 focus:border-[var(--bg-accent)]"
                                        onChange={handleImageChange}
                                        {...register('productImage')}
                                    />
                                    {previewImage && (
                                        <div className="mt-4 flex justify-center">
                                            <img
                                                src={previewImage}
                                                alt="Preview"
                                                className="w-40 h-40 object-contain rounded-lg shadow-md"
                                            />
                                        </div>
                                    )}
                                </div>

                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Description
                                        <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                                    </label>
                                    <textarea
                                        className="w-full h-32 p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all resize-none text-sm"
                                        {...register('description', { required: true })}
                                    />
                                    {errors.description && (
                                        <span className="text-red-500 text-sm mt-1">Description is required</span>
                                    )}
                                </div>

                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        Tags
                                    </label>
                                    <ReactTags
                                        tags={tags.map((tag, index) => ({
                                            id: index.toString(),
                                            text: tag
                                        }))}
                                        handleDelete={handleDeleteTag}
                                        handleAddition={handleAddTag}
                                        inputFieldPosition="bottom"
                                        placeholder="Add tags..."
                                        classNames={{
                                            tags: 'flex flex-wrap gap-2 mt-2',
                                            tag: 'px-2 py-1 text-xs font-medium rounded-full bg-[var(--bg-accent)]/10 custom-text-accent flex items-center gap-1',
                                            tagInput: 'w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm mt-2',
                                            remove: 'cursor-pointer hover:text-red-500'
                                        }}
                                    />
                                </div>

                                <div className="form-control">
                                    <label className="block text-sm font-medium custom-text-primary mb-1">
                                        External Link
                                        <span className="custom-text-secondary text-xs ml-1">(Optional)</span>
                                    </label>
                                    <input
                                        type="url"
                                        className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                        {...register('externalLink', {
                                            pattern: {
                                                value: /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/,
                                                message: "Please enter a valid URL"
                                            }
                                        })}
                                    />
                                    {errors.externalLink && (
                                        <span className="text-red-500 text-sm mt-1">{errors.externalLink.message}</span>
                                    )}
                                </div>

                                <div className="flex gap-4 justify-end">
                                    <button
                                        type="button"
                                        className="btn btn-sm custom-bg-secondary custom-text-primary rounded-lg text-sm hover:bg-[var(--bg-accent)]/10"
                                        onClick={() => setEditingProduct(null)}
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        className="btn btn-sm custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                                    >
                                        Save Changes
                                    </button>
                                </div>
                            </form>
                        </div>
                    </dialog>
                )}
            </div>
        </div>
    );
};

export default MyProducts;