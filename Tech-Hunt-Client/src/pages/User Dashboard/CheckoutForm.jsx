import { useState, useEffect } from 'react';
import { CardElement, useElements, useStripe } from "@stripe/react-stripe-js";
import useAxiosSecure from "../../hooks/useAxiosSecure";
import { Tag } from 'lucide-react';
import useAuth from '../../hooks/useAuth';
import { useNavigate, useLocation } from 'react-router-dom';
import { toast } from 'react-hot-toast';

const CheckoutForm = () => {
    const [error, setError] = useState('');
    const [clientSecret, setClientSecret] = useState('');
    const [couponCode, setCouponCode] = useState('');
    const [transactionId, setTransactionId] = useState('');
    const {user} = useAuth();
    const [appliedCoupon, setAppliedCoupon] = useState(null);
    const [processing, setProcessing] = useState(false);
    const [subscriptionAmount, setSubscriptionAmount] = useState(50); // Base price $50
    const stripe = useStripe();
    const elements = useElements();
    const axiosSecure = useAxiosSecure();
    const navigate = useNavigate();
    const location = useLocation();

    // Automatically apply coupon from query parameters
    useEffect(() => {
        const queryParams = new URLSearchParams(location.search);
        const coupon = queryParams.get('coupon');
        if (coupon) {
            setCouponCode(coupon);
            handleApplyCoupon(coupon);
        }
    }, [location.search]);

    // Verify coupon code
    const handleApplyCoupon = async (code = couponCode) => {
        try {
            const response = await axiosSecure.get(`/verify-coupon/${code}`);
            const coupon = response.data;
            
            const discountedAmount = 50 * (1 - coupon.discountAmount / 100);
            setSubscriptionAmount(discountedAmount);
            setAppliedCoupon(coupon);
            setError('');
        } catch (err) {
            if (err.response?.status === 404) {
                setError('Invalid coupon code');
            } else if (err.response?.status === 400) {
                setError('This coupon has expired');
            } else {
                setError('Error verifying coupon');
            }
            setAppliedCoupon(null);
            setSubscriptionAmount(50);
            console.error(err);
        }
    };

    useEffect(() => {
        if (subscriptionAmount > 0) {
            axiosSecure.post('/create-payment-intent', { price: subscriptionAmount })
                .then(res => {
                    setClientSecret(res.data.clientSecret);
                })
                .catch(err => {
                    console.error('Error creating payment intent:', err);
                    setError('Failed to initialize payment');
                });
        }
    }, [subscriptionAmount]);

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (!stripe || !elements || !clientSecret) {
            return;
        }

        setProcessing(true);
        setError('');

        try {
            // 1. Process the payment
            const { paymentIntent, error: confirmError } = await stripe.confirmCardPayment(
                clientSecret,
                {
                    payment_method: {
                        card: elements.getElement(CardElement),
                        billing_details: {
                            email: user?.email || 'anonymous',
                            name: user?.displayName || 'anonymous'
                        },
                    },
                }
            );

            if (confirmError) {
                setError(confirmError.message);
                return;
            }

            if (paymentIntent.status === 'succeeded') {
                // 2. Update user's membership status in the database
                await axiosSecure.patch(`/users/${user.email}`, {
                    membershipStatus: 'active',
                    subscriptionDate: new Date(),
                    paymentId: paymentIntent.id,
                    subscriptionAmount: subscriptionAmount,
                    couponUsed: appliedCoupon?.code || null
                });

                setTransactionId(paymentIntent.id);
                toast.success('Successfully subscribed to premium!');
                
                // 3. Navigate to profile page after successful subscription
                setTimeout(() => {
                    navigate('/dashboard/profile');
                }, 2000);
            }
        } catch (err) {
            setError('An error occurred during payment processing');
            console.error(err);
        } finally {
            setProcessing(false);
        }
    };

    return (
        <div className="max-w-md mx-auto p-6 rounded-lg shadow-lg">
            <h2 className="text-2xl font-bold mb-6">Subscribe to Premium</h2>
            
            <div className="mb-6">
                <p className="text-lg mb-2">Subscription Fee: ${subscriptionAmount.toFixed(2)}</p>
                {appliedCoupon && (
                    <div className="flex items-center gap-2 text-green-600 mb-2">
                        <Tag className="h-4 w-4" />
                        <span>{appliedCoupon.discountAmount}% discount applied</span>
                    </div>
                )}
            </div>

            <div className="mb-6">
                <div className="flex gap-2 mb-2">
                    <input
                        type="text"
                        placeholder="Enter coupon code"
                        className="input input-bordered flex-1"
                        value={couponCode}
                        onChange={(e) => setCouponCode(e.target.value)}
                    />
                    <button
                        className="btn btn-secondary"
                        onClick={() => handleApplyCoupon()}
                        disabled={!couponCode}
                    >
                        Apply
                    </button>
                </div>
            </div>

            <form onSubmit={handleSubmit}>
                <CardElement
                    options={{
                        style: {
                            base: {
                                fontSize: '16px',
                                color: '#424770',
                                '::placeholder': {
                                    color: '#aab7c4',
                                },
                            },
                            invalid: {
                                color: '#9e2146',
                            },
                        },
                    }}
                />
                <button 
                    className="btn btn-primary w-full mt-6" 
                    type="submit" 
                    disabled={!stripe || !clientSecret || processing}
                >
                    {processing ? 'Processing...' : `Pay $${subscriptionAmount.toFixed(2)}`}
                </button>
                
                {error && <p className="text-red-600 mt-4">{error}</p>}
                {transactionId && (
                    <div className="mt-4">
                        <p className="text-green-600">Payment Successful!</p>
                        <p className="text-sm">Transaction ID: {transactionId}</p>
                    </div>
                )}
            </form>
        </div>
    );
};

export default CheckoutForm;
