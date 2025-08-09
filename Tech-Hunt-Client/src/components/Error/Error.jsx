import Lottie from "lottie-react";
import errorpage from "../../assets/404.json";
import { Link } from "react-router-dom";

const Error = () => {
    return (
        <div className="flex items-center justify-center h-screen">
            <div className="text-center">
                <Lottie
                    className="mx-auto"
                    animationData={errorpage}
                    loop={true}
                />
                <Link
                    to="/"
                    className="btn bg-purple-500 text-white btn-lg"
                >
                    Back to Home
                </Link>
            </div>
        </div>
    );
};

export default Error;