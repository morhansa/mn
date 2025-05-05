<?php
declare(strict_types=1);

namespace MagoArab\WithoutEmail\Observer;

use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\Event\Observer;
use Magento\Sales\Model\Order;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Exception\NoSuchEntityException;
use MagoArab\WithoutEmail\Helper\Config;
use MagoArab\WithoutEmail\Helper\WhatsappService;

class OrderStatusChange implements ObserverInterface
{
    /**
     * @var CustomerRepositoryInterface
     */
    protected $customerRepository;
    
    /**
     * @var Config
     */
    protected $configHelper;
    
    /**
     * @var WhatsappService
     */
    protected $whatsappService;

    /**
     * Constructor
     *
     * @param CustomerRepositoryInterface $customerRepository
     * @param Config $configHelper
     * @param WhatsappService $whatsappService
     */
    public function __construct(
        CustomerRepositoryInterface $customerRepository,
        Config $configHelper,
        WhatsappService $whatsappService
    ) {
        $this->customerRepository = $customerRepository;
        $this->configHelper = $configHelper;
        $this->whatsappService = $whatsappService;
    }

    /**
     * Execute observer
     *
     * @param Observer $observer
     * @return void
     */
    public function execute(Observer $observer)
    {
        if (!$this->configHelper->isEnabled() || !$this->configHelper->isOrderNotificationsEnabled()) {
            return;
        }

        /** @var Order $order */
        $order = $observer->getEvent()->getOrder();
        if (!$order || !$order->getId()) {
            return;
        }
        
        // Get dependencies from ObjectManager
        $objectManager = \Magento\Framework\App\ObjectManager::getInstance();
        $dateTime = $objectManager->get(\Magento\Framework\Stdlib\DateTime\DateTime::class);
        $urlBuilder = $objectManager->get(\Magento\Framework\UrlInterface::class);
        $logger = $objectManager->get(\Psr\Log\LoggerInterface::class);
        
        // Check if notification is enabled for this status
        $enabledStatuses = $this->configHelper->getEnabledStatusesForNotification();
        $currentStatus = $order->getStatus();
        
        if (!in_array($currentStatus, $enabledStatuses)) {
            return;
        }
        
        // Get customer phone number
        $customerId = $order->getCustomerId();
        if (!$customerId) {
            return;
        }
        
        try {
            $customer = $this->customerRepository->getById($customerId);
            $phoneAttribute = $customer->getCustomAttribute('phone_number');
            
            if (!$phoneAttribute) {
                return;
            }
            
            $phoneNumber = $phoneAttribute->getValue();
            
            // Prepare comprehensive message parameters
            $params = [
                'order_id' => $order->getIncrementId(),
                'customer_name' => $customer->getFirstname() . ' ' . $customer->getLastname(),
                'order_total' => $order->getOrderCurrency()->formatPrecision(
                    $order->getGrandTotal(),
                    2,
                    [],
                    false
                ),
                'order_date' => $this->formatDate($order->getCreatedAt(), $dateTime),
                'payment_method' => $order->getPayment()->getMethodInstance()->getTitle(),
                'shipping_method' => $order->getShippingDescription(),
                'order_link' => $this->getOrderLink($order, $urlBuilder)
            ];
            
            // Add tracking number if available
            if ($currentStatus === 'shipped' || $currentStatus === 'complete') {
                $tracksCollection = $order->getTracksCollection();
                if ($tracksCollection->getSize() > 0) {
                    $track = $tracksCollection->getFirstItem();
                    $params['tracking_number'] = $track->getTrackNumber();
                }
            }
            
            // Add estimated delivery date if available
            if ($order->getShippingMethod()) {
                $params['delivery_date'] = $this->calculateDeliveryDate($order, $dateTime);
            }
            
            // Send notification
            $this->whatsappService->sendOrderStatusNotification($phoneNumber, $params, $currentStatus);
        } catch (NoSuchEntityException $e) {
            // Customer not found, ignore
        } catch (LocalizedException $e) {
            // Log error but don't stop execution
            $logger->error('WhatsApp notification error: ' . $e->getMessage());
        }
    }
    
    /**
     * Map Magento order status to notification status
     *
     * @param string $status
     * @return string|null
     */
    protected function mapOrderStatus(string $status): ?string
    {
        switch ($status) {
            case Order::STATE_PROCESSING:
                return 'processing';
            case Order::STATE_COMPLETE:
                return 'delivered';
            case 'shipped':
            case 'shipping':
                return 'shipped';
            default:
                return null;
        }
    }
    
    /**
     * Format date for display
     */
    protected function formatDate($date, $dateTime): string
    {
        try {
            return $dateTime->date('M d, Y', $date);
        } catch (\Exception $e) {
            return date('M d, Y');
        }
    }

    /**
     * Get order link for customer
     */
    protected function getOrderLink($order, $urlBuilder): string
    {
        return $urlBuilder->getUrl(
            'sales/order/view',
            ['order_id' => $order->getId()]
        );
    }

    /**
     * Calculate estimated delivery date
     */
    protected function calculateDeliveryDate($order, $dateTime): string
    {
        // Simple calculation - add 3-5 business days
        $days = 3; // Default
        $shippingMethod = $order->getShippingMethod();
        
        if (strpos($shippingMethod, 'express') !== false) {
            $days = 1;
        } elseif (strpos($shippingMethod, 'priority') !== false) {
            $days = 2;
        }
        
        try {
            $deliveryDate = new \DateTime();
            $deliveryDate->modify("+{$days} weekdays");
            return $dateTime->date('M d, Y', $deliveryDate->format('Y-m-d'));
        } catch (\Exception $e) {
            return date('M d, Y', strtotime("+{$days} weekdays"));
        }
    }
}