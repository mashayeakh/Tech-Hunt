import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import { Tag } from 'lucide-react';
import useAuth from "../../hooks/useAuth";
import useAxiosPublic from '../../hooks/useAxiosPublic';
import { Helmet } from 'react-helmet-async';

const AddProduct = () => {
    const navigate = useNavigate();
    const { user } = useAuth();
    const axiosPublic = useAxiosPublic();
    const [isLoading, setIsLoading] = useState(false);
    const [userStatus, setUserStatus] = useState(null);
    const [tags, setTags] = useState([]);
    const [previewImage, setPreviewImage] = useState('');
    const [currentTag, setCurrentTag] = useState('');

    const { register, handleSubmit, setValue, reset, formState: { errors } } = useForm({
        defaultValues: {
            ownerName: user?.displayName || '',
            ownerEmail: user?.email || '',
            ownerImage: user?.photoURL || '',
            tags: [],
            productImage: null
        }
    });

    useEffect(() => {
        const checkUserStatus = async () => {
            try {
                const response = await axiosPublic.get(`/users/${user?.email}`);
                setUserStatus(response.data);
            } catch (error) {
                console.error('Error fetching user status:', error);
            }
        };

        if (user?.email) {
            checkUserStatus();
        }
    }, [user, axiosPublic]);

    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setPreviewImage(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleAddTag = () => {
        if (currentTag.trim() && !tags.includes(currentTag.trim())) {
            const newTags = [...tags, currentTag.trim()];
            setTags(newTags);
            setValue('tags', newTags);
            setCurrentTag('');
        }
    };

    const handleRemoveTag = (tagToRemove) => {
        const newTags = tags.filter(tag => tag !== tagToRemove);
        setTags(newTags);
        setValue('tags', newTags);
    };

    const onSubmit = async (data) => {
        try {
            setIsLoading(true);

            const imageFile = { image: data.productImage[0] };
            const imgbbFormData = new FormData();
            imgbbFormData.append('image', data.productImage[0]);

            const imgbbResponse = await axiosPublic.post(
                `https://api.imgbb.com/1/upload?key=${import.meta.env.VITE_IMAGE_HOSTING_KEY}`,
                imgbbFormData
            );

            if (imgbbResponse.data.success) {
                const productItem = {
                    productName: data.productName,
                    productImage: imgbbResponse.data.data.display_url,
                    description: data.description,
                    ownerName: user.displayName,
                    ownerImage: user.photoURL,
                    ownerEmail: user.email,
                    externalLink: data.externalLink,
                    tags: tags,
                    status: 'pending',
                    upvotes: 0,
                    timestamp: new Date().toISOString(),
                };

                const productRes = await axiosPublic.post('/products', productItem);

                if (productRes.data.insertedId) {
                    reset();
                    setPreviewImage('');
                    setTags([]);
                    Swal.fire({
                        position: "top-end",
                        icon: "success",
                        title: `${data.productName} added successfully!`,
                        text: "Your product is pending moderator approval",
                        showConfirmButton: false,
                        timer: 2000
                    });
                    setTimeout(() => {
                        navigate('/dashboard/myProducts');
                    }, 2000);
                }
            }
        } catch (error) {
            if (error.response?.status === 403) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Product Limit Reached',
                    text: 'Free users can only add one product. Would you like to upgrade to premium?',
                    showCancelButton: true,
                    confirmButtonColor: 'var(--bg-accent)',
                    cancelButtonColor: '#d33',
                    confirmButtonText: 'Upgrade Now',
                    cancelButtonText: 'Maybe Later'
                }).then((result) => {
                    if (result.isConfirmed) {
                        navigate('/dashboard/payment');
                    }
                });
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Failed to add product. Please try again.'
                });
            }
            console.error('Error adding product:', error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Add Product | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <div className="custom-bg-secondary rounded-xl shadow-lg p-8">
                    <h2 className="chakra text-3xl font-bold text-center mb-6 custom-text-primary">
                        Add New Product
                    </h2>

                    {(!userStatus?.membershipStatus || userStatus.membershipStatus !== 'active') && (
                        <div className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-accent)]/10 custom-text-accent rounded-lg mb-6">
                            <Tag className="h-5 w-5" />
                            <div>
                                <span className="font-medium">Free User Notice:</span> You can add only one product.
                                <button
                                    className="btn btn-link btn-sm custom-text-accent hover:custom-text-accent"
                                    onClick={() => navigate('/dashboard/payment')}
                                >
                                    Upgrade to Premium
                                </button>
                            </div>
                        </div>
                    )}

                    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                        <div className="form-control">
                            <label className="block text-sm font-medium custom-text-primary mb-1">
                                Product Name
                                <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                            </label>
                            <input
                                type="text"
                                placeholder="Enter product name"
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
                                <span className="custom-text-secondary text-xs ml-1">(Required)</span>
                            </label>
                            <input
                                type="file"
                                accept="image/*"
                                className="file-input file-input-bordered w-full custom-bg-primary custom-text-primary border-[var(--bg-accent)]/20 focus:border-[var(--bg-accent)]"
                                {...register('productImage', { required: true })}
                                onChange={handleImageChange}
                            />
                            {errors.productImage && (
                                <span className="text-red-500 text-sm mt-1">Product image is required</span>
                            )}
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
                                required
                                className="w-full h-32 p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all resize-none text-sm"
                                placeholder="Describe your product in detail..."
                                {...register('description')}
                            />
                        </div>

                        <div className="custom-bg-primary rounded-xl p-6 border border-[var(--bg-accent)]/10">
                            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                                <div className="relative">
                                    {user?.photoURL ? (
                                        <img
                                            src={user.photoURL}
                                            alt="Owner"
                                            className="w-20 h-20 rounded-full object-cover border-2 border-[var(--bg-accent)]/30 shadow-md"
                                        />
                                    ) : (
                                        <div className="w-20 h-20 rounded-full bg-[var(--bg-accent)]/10 flex items-center justify-center text-2xl custom-text-accent font-medium">
                                            {user?.displayName?.charAt(0).toUpperCase() || 'U'}
                                        </div>
                                    )}
                                    <div className="badge badge-sm absolute -top-2 right-0 bg-[var(--bg-accent)] text-white">
                                        Owner
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <h3 className="chakra text-xl font-bold custom-text-primary">
                                        {user?.displayName}
                                    </h3>
                                    <div className="flex flex-col gap-1 text-sm custom-text-secondary">
                                        <span>Email: {user?.email}</span>
                                        <span>Product Owner</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="form-control">
                            <label className="block text-sm font-medium custom-text-primary mb-1">
                                Tags
                            </label>
                            <div className="flex gap-2 items-center">
                                <input
                                    type="text"
                                    value={currentTag}
                                    onChange={(e) => setCurrentTag(e.target.value)}
                                    placeholder="Add tags..."
                                    className="w-full p-3 custom-bg-primary custom-text-primary border border-[var(--bg-accent)]/20 rounded-lg focus:border-[var(--bg-accent)] outline-none transition-all text-sm"
                                    onKeyPress={(e) => {
                                        if (e.key === 'Enter') {
                                            e.preventDefault();
                                            handleAddTag();
                                        }
                                    }}
                                />
                                <button
                                    type="button"
                                    className="btn custom-bg-accent text-white rounded-lg text-sm hover:opacity-90"
                                    onClick={handleAddTag}
                                >
                                    Add Tag
                                </button>
                            </div>
                            <div className="flex flex-wrap gap-2 mt-2">
                                {tags.map((tag, index) => (
                                    <div
                                        key={index}
                                        className="px-2 py-1 text-xs font-medium rounded-full bg-[var(--bg-accent)]/10 custom-text-accent flex items-center gap-1"
                                    >
                                        {tag}
                                        <button
                                            type="button"
                                            className="text-xs hover:text-red-500"
                                            onClick={() => handleRemoveTag(tag)}
                                        >
                                            ×
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="form-control">
                            <label className="block text-sm font-medium custom-text-primary mb-1">
                                External Link
                                <span className="custom-text-secondary text-xs ml-1">(Optional)</span>
                            </label>
                            <input
                                type="url"
                                placeholder="https://example.com"
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

                        <button
                            type="submit"
                            className="btn btn-lg custom-bg-accent text-white rounded-lg w-full hover:opacity-90 text-sm"
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <>
                                    <span className="loading loading-spinner"></span>
                                    Processing...
                                </>
                            ) : (
                                'Add Product'
                            )}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default AddProduct;