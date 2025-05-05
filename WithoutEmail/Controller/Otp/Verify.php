<?php
namespace MagoArab\WithoutEmail\Controller\Otp;

use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Customer\Model\Session as CustomerSession;
use MagoArab\WithoutEmail\Helper\Config;
use MagoArab\WithoutEmail\Model\OtpRateLimit;
use Psr\Log\LoggerInterface;

class Verify implements HttpPostActionInterface, CsrfAwareActionInterface
{
    private RequestInterface $request;
    private JsonFactory $resultJsonFactory;
    private CustomerSession $customerSession;
    private Config $configHelper;
    private OtpRateLimit $otpRateLimit;
    private LoggerInterface $logger;

    public function __construct(
        RequestInterface $request,
        JsonFactory $resultJsonFactory,
        CustomerSession $customerSession,
        Config $configHelper,
        OtpRateLimit $otpRateLimit,
        LoggerInterface $logger
    ) {
        $this->request = $request;
        $this->resultJsonFactory = $resultJsonFactory;
        $this->customerSession = $customerSession;
        $this->configHelper = $configHelper;
        $this->otpRateLimit = $otpRateLimit;
        $this->logger = $logger;
    }

    public function execute()
    {
        $resultJson = $this->resultJsonFactory->create();
        
        try {
            if (!$this->configHelper->isEnabled()) {
                throw new \Exception('This feature is not enabled.');
            }
            
            $phoneNumber = $this->request->getParam('phone_number');
            $otpCode = $this->request->getParam('otp_code');
            
            if (empty($phoneNumber) || empty($otpCode)) {
                throw new \Exception('Phone number and OTP code are required.');
            }
            
            // Get OTP data from session
            $otpData = $this->customerSession->getData('otp_' . $phoneNumber);
            
            if (!$otpData || !isset($otpData['code']) || !isset($otpData['expiry'])) {
                throw new \Exception('OTP has not been sent. Please request a new OTP.');
            }
            
            // Check attempts
            if (isset($otpData['attempts']) && $otpData['attempts'] >= 3) {
                $this->customerSession->unsetData('otp_' . $phoneNumber);
                throw new \Exception('Too many failed attempts. Please request a new OTP.');
            }
            
            // Check if OTP has expired
            $currentTime = new \DateTime();
            $expiry = new \DateTime($otpData['expiry']);
            
            if ($currentTime > $expiry) {
                $this->customerSession->unsetData('otp_' . $phoneNumber);
                throw new \Exception('OTP has expired. Please request a new OTP.');
            }
            
            // Verify OTP
            if ($otpData['code'] !== $otpCode) {
                $otpData['attempts'] = ($otpData['attempts'] ?? 0) + 1;
                $this->customerSession->setData('otp_' . $phoneNumber, $otpData);
                
                $this->otpRateLimit->logAttempt($phoneNumber, false);
                
                throw new \Exception('Invalid OTP code. Please try again.');
            }
            
            // Mark OTP as verified
            $otpData['verified'] = true;
            $this->customerSession->setData('otp_' . $phoneNumber, $otpData);
            
            return $resultJson->setData([
                'success' => true,
                'message' => __('OTP verified successfully.')
            ]);
            
        } catch (\Exception $e) {
            $this->logger->error('OTP Verify Error: ' . $e->getMessage());
            return $resultJson->setData([
                'success' => false,
                'message' => $e->getMessage()
            ]);
        }
    }

    public function createCsrfValidationException(RequestInterface $request): ?InvalidRequestException
    {
        return null;
    }

    public function validateForCsrf(RequestInterface $request): ?bool
    {
        return true;
    }
}