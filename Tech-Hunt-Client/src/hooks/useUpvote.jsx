import { useQuery } from "@tanstack/react-query";
import useAxiosSecure from "./useAxiosSecure";
import useAuth from "./useAuth";

const useUpvote = () => {
    // tanstack query 

    const axiosSecure = useAxiosSecure();
    const {user} = useAuth();
    const { refetch, data: upvote = [] } = useQuery({
        queryKey: ['upvote', user?.email],
        queryFn: async () => {
            const res = await axiosSecure.get(`/upvotes?email=${user.email}`)
            return res.data;
        }
    })
    return [upvote, refetch]
};

export default useUpvote;