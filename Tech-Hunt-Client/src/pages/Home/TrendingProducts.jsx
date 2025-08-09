import { useMemo } from "react";
import ProductItem from "../Shared/ProductItem";
import { Link } from "react-router-dom";
import useProducts from "../../hooks/useProducts";
import { Loader2 } from "lucide-react";

const TrendingProducts = () => {
  const [products, loading] = useProducts();

  const trending = useMemo(() => {
    return products
      .sort((a, b) => (b.upvotes || 0) - (a.upvotes || 0))
      .slice(0, 6);
  }, [products]);

  if (loading) {
    return (
      <div className="text-center py-12">
        <Loader2 size={40} className="animate-spin custom-text-accent mx-auto" />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 max-w-5xl font-inter">
      <div className="text-center my-12">
        <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
          Trending
        </span>
        <h2 className="chakra text-2xl lg:text-4xl font-bold custom-text-primary">
          Trending Products
        </h2>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {trending.map((product) => (
          <ProductItem key={product._id} product={product} />
        ))}
      </div>
      <div className="text-center my-8">
        <Link
          to="/products"
          className="px-6 py-3 custom-bg-accent text-white rounded-lg text-sm font-medium transition-all hover:scale-105 hover:shadow-lg tooltip tooltip-bottom"
          data-tip="View all products"
        >
          Show All Products
        </Link>
      </div>
    </div>
  );
};

export default TrendingProducts;