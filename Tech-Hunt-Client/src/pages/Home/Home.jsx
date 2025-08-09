import { Helmet } from "react-helmet-async";
import Banner from "./Banner";
import FeaturedProducts from "./FeaturedProducts";
import TrendingProducts from "./TrendingProducts";
import CouponBanner from "./CouponBanner";
import FAQ from "./FAQ";
import Newsletter from "./Newsletter";
import Community from "./Community";
import Impact from "./Impact";
import Testimonials from "./Testimonials";

const Home = () => {
    return (
        <div>
            <Helmet>
                <title>Home | Tech Hunt</title>
            </Helmet>
            <div>
                <Banner></Banner>
                <FeaturedProducts></FeaturedProducts>
                <TrendingProducts></TrendingProducts>
                <Community></Community>
                <Impact></Impact>
                <CouponBanner></CouponBanner>
                <Testimonials></Testimonials>
                <FAQ></FAQ>
                <Newsletter></Newsletter>
            </div>
        </div>
    );
};

export default Home;