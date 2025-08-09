import { FaFacebookSquare, FaGithub, FaLinkedin } from "react-icons/fa";

const Footer = () => {
    return (
        <footer className="custom-bg-primary p-8 font-inter">
            <div className="container mx-auto max-w-5xl text-center">
                <img className="w-8 mx-auto mb-2" src="/logo 2.png" alt="Tech Hunt Logo" />
                <p className="chakra text-xl font-bold custom-text-primary mb-2">Tech Hunt</p>
                <p className="custom-text-secondary mb-2">Providing reliable tech since 2025</p>
                <p className="custom-text-secondary text-sm">Copyright © {new Date().getFullYear()} - All rights reserved</p>
                <nav>
                    <div className="flex justify-center gap-6 mt-4">
                        <a href="https://www.facebook.com/ajm.fajlayrabby" className="custom-text-accent hover:opacity-80 transition-opacity">
                            <FaFacebookSquare className="text-2xl" />
                        </a>
                        <a href="https://www.linkedin.com/in/ornobaadi" className="custom-text-accent hover:opacity-80 transition-opacity">
                            <FaLinkedin className="text-2xl" />
                        </a>
                        <a href="https://github.com/ornobaadi" className="custom-text-accent hover:opacity-80 transition-opacity">
                            <FaGithub className="text-2xl" />
                        </a>
                    </div>
                </nav>
            </div>
        </footer>
    );
};

export default Footer;