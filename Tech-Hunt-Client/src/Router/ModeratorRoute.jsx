import { Navigate, useLocation } from "react-router-dom";
import useModerator from "../hooks/useModerator";
import useAuth from "../hooks/useAuth";

const ModeratorRoute = ({children}) => {
    const {user, loading} = useAuth();
    const [isModerator, isModeratorLoading] = useModerator();
    const location = useLocation();

    if (loading || isModeratorLoading) {
        return <div className="flex justify-center my-10">
            <span className="loading loading-bars loading-xl"></span>
        </div>
    }

    if (user && isModerator) {
        return children;
    }
    return <Navigate to='/' state={{ from: location }} replace></Navigate>
};

export default ModeratorRoute;