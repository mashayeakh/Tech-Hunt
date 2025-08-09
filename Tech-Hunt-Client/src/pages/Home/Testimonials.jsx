import { useState } from "react";
import { motion } from "framer-motion";
import { ChevronLeft, ChevronRight } from "lucide-react";

const Testimonials = () => {
  const [activeIndex, setActiveIndex] = useState(0);
  const testimonials = [
    {
      quote: "Tech Hunt helped my AI code assistant get 5,000 early users, which was crucial for collecting training data. This platform directly contributed to our $2M seed round.",
      name: "Alex Chen",
      role: "Founder, CodeBuddy AI",
      avatar: "https://randomuser.me/api/portraits/men/82.jpg",
    },
    {
      quote: "As an investor, Tech Hunt has become my secret weapon for spotting emerging tech trends before they hit mainstream. I've discovered three portfolio companies here.",
      name: "Sarah Williams",
      role: "Partner, FutureFund VC",
      avatar: "https://randomuser.me/api/portraits/women/79.jpg",
    },
    {
      quote: "I launched my accessibility tool on Tech Hunt and the community feedback transformed our product roadmap. Their feature suggestions were more valuable than months of internal planning.",
      name: "Marcus Johnson",
      role: "Creator, AccessifyWeb",
      avatar: "https://randomuser.me/api/portraits/men/29.jpg",
    },
  ];

  const nextSlide = () => {
    setActiveIndex((activeIndex + 1) % testimonials.length);
  };

  const prevSlide = () => {
    setActiveIndex((activeIndex - 1 + testimonials.length) % testimonials.length);
  };

  return (
    <section className="py-12 custom-bg-primary font-inter">
      <div className="container mx-auto px-4 max-w-5xl">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
            Testimonials
          </span>
          <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
            Success Stories
          </h2>
          <p className="text-sm custom-text-secondary max-w-3xl mx-auto">
            Hear from the creators and community members who've experienced the Tech Hunt advantage.
          </p>
        </motion.div>

        <motion.div
          className="relative max-w-4xl mx-auto"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <div className="relative overflow-hidden rounded-xl custom-bg-secondary shadow-lg">
            <motion.div
              className="flex"
              animate={{ x: `-${activeIndex * 100}%` }}
              transition={{ duration: 0.5, ease: "easeInOut" }}
            >
              {testimonials.map((testimonial, index) => (
                <div
                  key={index}
                  className="min-w-full p-6 md:p-10 flex flex-col items-center text-center"
                >
                  <blockquote className="text-lg italic custom-text-primary mb-6">
                    "{testimonial.quote}"
                  </blockquote>
                  <div className="flex flex-col items-center">
                    <img
                      src={testimonial.avatar}
                      alt={testimonial.name}
                      className="w-14 h-14 rounded-full border-2 border-[var(--bg-accent)]/20 mb-4"
                    />
                    <div className="text-lg font-semibold custom-text-primary">{testimonial.name}</div>
                    <div className="text-sm custom-text-secondary">{testimonial.role}</div>
                  </div>
                </div>
              ))}
            </motion.div>

            {/* Navigation Arrows */}
            <button
              onClick={prevSlide}
              className="absolute left-4 top-1/2 transform -translate-y-1/2 w-8 h-8 flex items-center justify-center rounded-full custom-bg-accent text-white hover:scale-110 transition-all tooltip tooltip-bottom"
              data-tip="Previous testimonial"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={nextSlide}
              className="absolute right-4 top-1/2 transform -translate-y-1/2 w-8 h-8 flex items-center justify-center rounded-full custom-bg-accent text-white hover:scale-110 transition-all tooltip tooltip-bottom"
              data-tip="Next testimonial"
            >
              <ChevronRight size={16} />
            </button>

            {/* Dots */}
            <div className="absolute bottom-4 left-0 right-0 flex justify-center space-x-2">
              {testimonials.map((_, index) => (
                <button
                  key={index}
                  onClick={() => setActiveIndex(index)}
                  className={`w-2 h-2 rounded-full transition-colors ${
                    index === activeIndex ? "custom-bg-accent" : "bg-[var(--bg-accent)]/20"
                  }`}
                ></button>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default Testimonials;