import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import useAxiosSecure from '../../hooks/useAxiosSecure';
import { Helmet } from 'react-helmet-async';

const Statistics = () => {
    const axiosSecure = useAxiosSecure();

    const { data: products = [] } = useQuery({
        queryKey: ['products'],
        queryFn: async () => {
            const res = await axiosSecure.get('/products');
            return res.data;
        }
    });

    const { data: users = [] } = useQuery({
        queryKey: ['users'],
        queryFn: async () => {
            const res = await axiosSecure.get('/users');
            return res.data;
        }
    });

    const { data: reviews = [] } = useQuery({
        queryKey: ['reviews'],
        queryFn: async () => {
            const res = await axiosSecure.get('/reviews');
            return res.data;
        }
    });

    const acceptedProducts = products.filter(product => product.status === 'accepted').length;
    const pendingProducts = products.filter(product => !product.status || product.status === 'pending').length;
    const rejectedProducts = products.filter(product => product.status === 'rejected').length;

    const pieData = [
        { name: 'Accepted Products', value: acceptedProducts, color: '#34D399' }, // Green
        { name: 'Pending Products', value: pendingProducts, color: '#FBBF24' }, // Yellow
        { name: 'Rejected Products', value: rejectedProducts, color: '#F87171' }, // Red
        { name: 'Total Users', value: users.length, color: '#60A5FA' }, // Blue
        { name: 'Total Reviews', value: reviews.length, color: '#A78BFA' } // Purple
    ];

    return (
        <div className="custom-bg-primary min-h-screen py-12 font-inter">
            <Helmet>
                <title>Statistics | Tech Hunt</title>
            </Helmet>
            <div className="container mx-auto px-4 max-w-5xl">
                <h2 className="chakra text-3xl font-bold text-center mb-12 custom-text-primary">
                    Statistics Overview
                </h2>

                <div className="custom-bg-secondary rounded-xl shadow-lg p-8 mb-8">
                    <div className="h-96">
                        <ResponsiveContainer>
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    label={({ name, value }) => `${name}: ${value}`}
                                    outerRadius={120}
                                    dataKey="value"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: 'var(--bg-secondary)',
                                        color: 'var(--text-primary)',
                                        border: '1px solid var(--bg-accent)',
                                        borderRadius: '8px'
                                    }}
                                />
                                <Legend
                                    layout="vertical"
                                    align="right"
                                    verticalAlign="middle"
                                    formatter={(value) => (
                                        <span className="custom-text-primary text-sm">{value}</span>
                                    )}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Total Products</h3>
                        <p className="text-3xl font-semibold custom-text-accent">{products.length}</p>
                    </div>
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Total Users</h3>
                        <p className="text-3xl font-semibold custom-text-accent">{users.length}</p>
                    </div>
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Total Reviews</h3>
                        <p className="text-3xl font-semibold custom-text-accent">{reviews.length}</p>
                    </div>
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Accepted Products</h3>
                        <p className="text-3xl font-semibold text-green-500">{acceptedProducts}</p>
                    </div>
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Pending Products</h3>
                        <p className="text-3xl font-semibold text-yellow-500">{pendingProducts}</p>
                    </div>
                    <div className="custom-bg-secondary rounded-xl shadow-lg p-6 text-center">
                        <h3 className="chakra text-lg font-bold custom-text-primary mb-2">Rejected Products</h3>
                        <p className="text-3xl font-semibold text-red-500">{rejectedProducts}</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Statistics;