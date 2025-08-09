import ProductItem from "../Shared/ProductItem";
import useProducts from "../../hooks/useProducts";
import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

const FeaturedProducts = () => {
  const [products] = useProducts();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const featured = products
    .filter((product) => product.featured === true)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, Math.max(4, products.length));

  useEffect(() => {
    if (products.length > 0) {
      setLoading(false);
    }
  }, [products]);

  if (loading) {
    return (
      <div className="text-center py-12">
        <Loader2 size={40} className="animate-spin custom-text-accent mx-auto" />
      </div>
    );
  }

  if (error) {
    return <div className="text-center text-red-500 text-sm py-12">Error: {error}</div>;
  }

  if (featured.length === 0) {
    return <div className="text-center text-sm custom-text-secondary py-12">No featured products available.</div>;
  }

  return (
    <div className="container mx-auto px-4 max-w-5xl font-inter">
      <div className="text-center my-12">
        <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
          Featured
        </span>
        <h2 className="chakra text-2xl lg:text-4xl font-bold custom-text-primary">
          Featured Products
        </h2>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {featured.map((product) => (
          <ProductItem key={product._id} product={product} />
        ))}
      </div>
    </div>
  );
};

export default FeaturedProducts;